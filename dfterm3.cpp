// The Dfterm3 plugin.
//
// To avoid confusion, this is *not* Dfterm3 itself; just a plugin to talk
// to Dfterm3.
//
// This grabs the data that the Dfterm3 wants and needs and sends it over
// with protobuf.
//
// Dfterm3 is a software for playing Dwarf Fortress remotely:
// <https://github.com/Noeda/dfterm3>
//

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "SDL_events.h"
#include "SDL_keysym.h"

#include "Core.h"
#include "VersionInfo.h"
#include "MemAccess.h"
#include <Console.h>
#include <PluginManager.h>
#include <Export.h>
#include <modules/Screen.h>
#include "PassiveSocket.h"
#include "ActiveSocket.h"
#include "DataDefs.h"
#include "df/graphic.h"
#include "df/enabler.h"
#include "df/renderer.h"

#include <set>

#include "dfterm3.pb.h"
#include "RemoteServer.h"

extern "C" {
    extern const char* __progname_full;
#ifndef _WIN32
    extern int SDL_PushEvent( SDL::Event* event );
#endif
};

static int (*mySDL_PushEvent)( SDL::Event* event ) = 0;
static void initialize_SDL_PushEvent( void );

using namespace DFHack;
using namespace std;
using namespace dfterm3;

using namespace df::enums;
using df::global::gps;
using df::global::enabler;

DFHACK_PLUGIN("dfterm3");
DFHACK_PLUGIN_IS_ENABLED(is_enabled);

struct Dfterm3Client
{
    CActiveSocket* client_socket;
    bool handshake_complete;
    bool acknowledgement_complete;

    uint32_t incoming_message_len;
    bool incoming_message_len_received;
    string incoming_message;
    string consuming_message;

    string send_buffer;

    void tryReceiveIncomingMessageLen()
    {
        if ( !incoming_message_len_received &&
              incoming_message.size() >= sizeof(uint32_t) ) {
            uint32_t rec = *((uint32_t*) incoming_message.data());
            incoming_message_len = ntohl( rec );
            incoming_message_len_received = true;
        }
    }

    bool tryConsumeMessage()
    {
        tryReceiveIncomingMessageLen();
        if ( incoming_message_len_received &&
             incoming_message_len + sizeof(uint32_t) <=
             incoming_message.size() ) {
            consuming_message =
                incoming_message.substr( sizeof(uint32_t)
                                       , incoming_message_len );
            incoming_message =
                incoming_message.substr( sizeof(uint32_t)+incoming_message_len
                                       , string::npos );
            incoming_message_len_received = false;
            return true;
        }
        return false;
    }

    Dfterm3Client() : client_socket(NULL)
                    , handshake_complete(false)
                    , acknowledgement_complete(false)
                    , incoming_message_len(0)
                    , incoming_message_len_received(false)
    {
    }

    ~Dfterm3Client()
    {
        if ( client_socket ) {
            delete client_socket;
        }
    }
};

enum MaybeUseProtobuf { UseProtobuf, DontUseProtobuf };

// From dfterm3_strerror.cpp. Turns an `errno` error code to a string.
string errnoToString( int error_number );

static int updates_per_second = 20;
static uint32_t last_time_updated = 0;

// Stop and start
static command_result startDfterm3 ( color_ostream &out
                                   , std::vector <std::string> &parameters );
static command_result stopDfterm3 ( color_ostream &out
                                  , std::vector <std::string> &parameters );
static void haltDfterm3();

// Network-related functions
static void cleanlyClearClients();
static void checkForNewConnections();
static void updateAllClients( color_ostream &out );
static bool handleClientSocket( color_ostream &out
                              , Dfterm3Client* client );
static bool sendHandshaking( color_ostream &out, Dfterm3Client* client );
static bool expectAcknowledgement( Dfterm3Client* client, color_ostream &out );
static bool flushClient( Dfterm3Client* client );
static bool sendPrefixedData( Dfterm3Client* client
                            , const uint8_t* data
                            , const uint32_t data_size
                            , MaybeUseProtobuf = UseProtobuf );
static bool sendData( Dfterm3Client* client
                    , const uint8_t* data
                    , const uint32_t data_size );
static bool sendScreenData( color_ostream &out, Dfterm3Client* client );
static void handleInput( Dfterm3Client* client, color_ostream &out );

// Magic cookies and port files
static bool makeMagicCookieFile( color_ostream &out );
static bool makePortFile( uint16_t port, color_ostream &out );
static void unlinkMagicCookieFile();
static void unlinkPortFile();
static bool initializeMagicCookieContents( color_ostream &out );

// Global variables (inside this plugin)
static bool dfterm3_running = false;
static CPassiveSocket listener_socket;
static set<Dfterm3Client*> clients;
static string magic_cookie_file = ".dfterm3-cookie";
static string magic_cookie_contents;


DFhackCExport command_result plugin_init ( color_ostream &out
                                         , std::vector<PluginCommand>
                                               &commands )
{
    initialize_SDL_PushEvent();

    commands.push_back(PluginCommand(
       "start-dfterm3"
     , "Allow Dfterm3 to find this Dwarf Fortress process."
     , startDfterm3
     , false
     , "Dfterm3 can find Dwarf Fortress processes by looking for open ports "
       "that Dfhack opens for it through this plugin. You need to enable the "
       "port first, however.\n\n"
       "This does nothing if the service has already been started. The "
       "service will be started listening on 127.0.0.1 so it cannot be "
       "connected to from outside your computer.") );

    commands.push_back(PluginCommand(
       "stop-dfterm3"
     , "Stops any connections to Dfterm3 and disallows Dfterm3 from finding "
       "this Dwarf Fortress process."
     , stopDfterm3
     , false
     , "This is the opposite of start-dfterm3.") );

    if ( getenv( "START_DFTERM3" ) ) {
        std::vector<std::string> empty;
        startDfterm3( out, empty );
    }

    return CR_OK;
}

DFhackCExport command_result plugin_shutdown ( color_ostream &out )
{
    haltDfterm3();
    return CR_OK;
}

DFhackCExport command_result plugin_onupdate( color_ostream &out )
{
    std::vector<std::string> empty;
    if ( !dfterm3_running ) {
        return CR_OK;
    }

    // Check for new connections.
    checkForNewConnections();

    Core &c = Core::getInstance();
    uint32_t now = c.p->getTickCount();

    if ( now > last_time_updated + (1000/updates_per_second) ||
         now < last_time_updated ) {
        updateAllClients( out );
        last_time_updated = now;
    }
    return CR_OK;
}

static void updateAllClients( color_ostream &out )
{
    set<Dfterm3Client*> removings; // which of the clients we should remove.

    // Send the screen data to each (alive) client.
    for ( set<Dfterm3Client*>::iterator i1 = clients.begin()
        ; i1 != clients.end()
        ; ++i1 ) {
        Dfterm3Client* client = *i1;

        if ( !handleClientSocket( out, client ) ) {
            delete client;
            removings.insert(client);
        }
    }

    // Remove disconnected clients.
    for ( set<Dfterm3Client*>::iterator i1 = removings.begin()
        ; i1 != removings.end()
        ; ++i1 ) {
        clients.erase( *i1 );
    }
}

static command_result startDfterm3 ( color_ostream &out
                                   , std::vector <std::string> & parameters )
{
    if ( dfterm3_running ) {
        out << "Dfterm3 service is already running." << endl;
        return CR_OK;
    }

    // We want some port from range 48000-48100
    // (somewhat below the ephemeral ports). We'll take the first port on
    // which the listening succeeds.
    //
    // This makes a hard limit of exactly 101 Dwarf Fortresses that can be
    // run at the same time for Dfterm3.
    //
    // TODO: Make this configurable. Maybe someone wants to run 10001 Dwarf
    //       Fortresses? Then again, we still have a theoretical maximum at
    //       65536 Dwarf Fortresses...
    //

    for ( int try_port = 48000; try_port <= 48100; ++try_port ) {
        listener_socket.Initialize();
        if ( listener_socket.Listen( (const uint8_t*) "127.0.0.1"
                                   , try_port ) ) {
            listener_socket.SetNonblocking();

            if ( !makePortFile( (uint16_t) try_port, out ) ) {
                out << "Failed to create a port file in "
                       "Dwarf Fortress directory. "
                       "Service not started." << endl;
                listener_socket.Close();
                return CR_FAILURE;
            }

            if ( makeMagicCookieFile( out ) ) {
                out << "Dfterm3 service started on port " <<
                       try_port << "." << endl;
                dfterm3_running = true;
                is_enabled = true;
                return CR_OK;
            } else {
                out << "Failed to create a magic cookie file in "
                       "Dwarf Fortress directory. "
                       "Service not started." << endl;
                listener_socket.Close();
                return CR_FAILURE;
            }
        }
    }
    out << "Failed to start Dfterm3 service." << endl;
    return CR_FAILURE;
}

static command_result stopDfterm3 ( color_ostream &out
                                  , std::vector <std::string> &parameters )
{
    if ( !dfterm3_running ) {
        out << "Dfterm3 service was not running anyway." << endl;
        return CR_OK;
    }

    haltDfterm3();

    out << "Stopped Dfterm3 service." << endl;
    return CR_OK;
}

// common code to make sure the service stops.
static void haltDfterm3()
{
    is_enabled = false;
    listener_socket.Close();
    cleanlyClearClients();
    unlinkMagicCookieFile();
    unlinkPortFile();
    dfterm3_running = false;
}

static bool makePortFile( uint16_t port, color_ostream &out )
{
    FILE* f = fopen( ".dfterm3-port", "wt" );
    if ( !f ) {
        return false;
    }
    fprintf( f, "%u\n", (unsigned int) port );
    fclose( f );
    return true;
}

static void unlinkPortFile()
{
#ifdef _WIN32
    DeleteFile( ".dfterm3-port" );
#else
    unlink( ".dfterm3-port" );
#endif
}

static bool makeMagicCookieFile( color_ostream &out )
{
    bool result = false;
    ssize_t wrote_bytes;

    if ( !initializeMagicCookieContents( out ) ) {
        return false;
    }

#ifndef _WIN32
    int fd = open( magic_cookie_file.c_str()
                 , O_CREAT | O_CLOEXEC | O_TRUNC | O_NOFOLLOW | O_WRONLY
                 , S_IRUSR | S_IWUSR );
    if ( fd == -1 ) {
        out << "I could not create the magic cookie file " <<
               magic_cookie_file << ": " << errnoToString( errno ) << endl;
        goto cleanup;
    }

    wrote_bytes = write( fd
                       , magic_cookie_contents.c_str()
                       , magic_cookie_contents.size() );

    if ( (size_t) wrote_bytes != magic_cookie_contents.size() ) {
        out << "I could not write to the magic cookie file " <<
               magic_cookie_file << endl;
        goto cleanup;
    }
#else
    FILE* f = fopen( magic_cookie_file.c_str(), "wb" );
    if ( !f ) {
        out << "I could not create the magic cookie file " <<
               magic_cookie_file << ": " << errnoToString( errno ) << endl;
        goto cleanup;
    }

    wrote_bytes = fwrite( magic_cookie_contents.c_str()
                        , 1
                        , magic_cookie_contents.size()
                        , f );

    if ( wrote_bytes != magic_cookie_contents.size() ) {
        out << "I could not write to the magic cookie file " <<
               magic_cookie_file << endl;
        goto cleanup;
    }
#endif

    result = true;

cleanup:
#ifndef _WIN32
    if ( fd != -1 ) close( fd );
#else
    if ( f ) fclose( f );
#endif
    return result;
}

static void unlinkMagicCookieFile()
{
#ifdef _WIN32
    DeleteFile( magic_cookie_file.c_str() );
#else
    unlink( magic_cookie_file.c_str() );
#endif
}

static void cleanlyClearClients()
{
    for ( set<Dfterm3Client*>::iterator i1 = clients.begin()
        ; i1 != clients.end()
        ; ++i1 ) {
        delete *i1;
    }
    clients.clear();
}

static void checkForNewConnections()
{
    Dfterm3Client* client = new Dfterm3Client;
    client->client_socket = listener_socket.Accept();

    if ( client->client_socket ) {
        client->client_socket->DisableNagleAlgoritm();
        clients.insert( client );
    } else {
        delete client;
    }
}

static bool expectAcknowledgement( Dfterm3Client* client, color_ostream &out )
{
    if ( !flushClient( client ) ) {
        return false;
    }
    if ( !client->tryConsumeMessage() ) {
        return true;
    }

    if ( client->consuming_message != magic_cookie_contents ) {
        return false;
    }

    client->acknowledgement_complete = true;
    return true;
}

static bool sendPrefixedData( Dfterm3Client* client
                            , const uint8_t* data
                            , const uint32_t data_size
                            , MaybeUseProtobuf proto )
{
    char* buf = (char*) malloc( data_size + sizeof(uint32_t) + 1 );
    if ( !buf ) {
        return false;
    }

    uint32_t send_len = htonl(data_size);
    uint8_t use_proto = (proto == UseProtobuf);

    *((uint32_t*) buf) = send_len;
    buf[sizeof(uint32_t)] = use_proto;
    memcpy( &buf[sizeof(uint32_t)+1], data, data_size );

    bool result = sendData( client, (uint8_t*) buf
                          , data_size + sizeof(uint32_t) + 1 );
    free( buf );
    return result;
}

static bool sendData( Dfterm3Client* client
                    , const uint8_t* data
                    , const uint32_t data_size )
{
    client->send_buffer += string( (char*) data, data_size );
    if ( client->send_buffer.size() == 0 ) {
        return true;
    }

    int result = client->client_socket->Send( (const uint8_t*)
                                              client->send_buffer.data()
                                            , client->send_buffer.size() );
    if ( result == -1 ) {
        int err = client->client_socket->GetSocketError();
        if ( err == CSimpleSocket::SocketInterrupted ) {
            return sendData( client, NULL, 0 );
        } else if ( err == CSimpleSocket::SocketEwouldblock ) {
            return true;
        }
        return false;
    }
    if ( result == 0 ) {
        return false;
    }
    client->send_buffer = client->send_buffer.substr( result );
    return true;
}

static bool sendHandshaking( color_ostream &out, Dfterm3Client* client )
{
    string sending;

#ifdef _WIN32
    uint64_t pid = (uint64_t) GetCurrentProcessId();

    WCHAR procname[ 1025 ];
    DWORD len = 1024;
    char utf8procname[ 1025 ];

    memset( procname, 0, sizeof(WCHAR) * 1025 );
    QueryFullProcessImageNameW( GetCurrentProcess(), 0, procname, &len );
    procname[1024] = 0;

    WideCharToMultiByte( CP_UTF8, 0, procname, -1, utf8procname, 1024, NULL, NULL );
    utf8procname[ 1025 ] = 0;

    string realpath_result = string(utf8procname);

    GetCurrentDirectoryW( 1024, procname );
    WideCharToMultiByte( CP_UTF8, 0, procname, -1, utf8procname, 1024, NULL, NULL );
    string path = string(utf8procname);
#else
    uint64_t pid = (uint64_t) getpgid(0);

    char path[PATH_MAX+1];
    char realpath_result[PATH_MAX+1];
    char* path2 = getcwd( path, PATH_MAX );
    path[PATH_MAX] = 0;

    if ( path != path2 ) {
        return false;
    }

    char* result = realpath(__progname_full, realpath_result);
    if ( !result ) {
        return false;
    }
#endif

    string version = Core::getInstance().vinfo->getVersion();

    Introduction i;
    i.set_df_version( version );
    i.set_path( string(path) );
    i.set_executable( string(realpath_result) );
    i.set_pid( pid );

    i.SerializeToString( &sending );

    // Note that we block at sending; DF could be suspended for a moment,
    // not to mention other Dfterm3 connections.
    //


    if ( !sendPrefixedData( client
                          , (const uint8_t*) sending.data()
                          , sending.size() ) ) {
        return false;
    }

    client->handshake_complete = true;
    client->client_socket->SetNonblocking();

    return true;
}

static bool initializeMagicCookieContents( color_ostream &out )
{
    unsigned char random_bytes[64];
#ifdef _WIN32
    HCRYPTPROV crypt;
    if ( !CryptAcquireContext( &crypt, NULL, NULL
                             , PROV_RSA_FULL
                             , CRYPT_VERIFYCONTEXT|CRYPT_SILENT ) ) {
        out << "Failed to acquire a crypt context. " << endl;
        return false;
    }

    int result = CryptGenRandom( crypt, 64, random_bytes );
    CryptReleaseContext( crypt, 0 );
    if ( !result ) {
        out << "Failed to generate random numbers for magic cookie file." <<
               endl;
        return false;
    }
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) f = fopen("/dev/random", "rb");
    if (!f) f = fopen("/dev/srandom", "rb");
    if (!f) {
        out << "I could not find and open a random number device "
               "file." << endl;
        return false;
    }

    size_t read_bytes = fread( random_bytes, 64, 1, f );
    fclose( f );

    if ( read_bytes != 1 ) {
        out << "I could not read random numbers from the random number device."
            << endl;
        return false;
    }
#endif

    // Make sure the bytes are ASCII-readable. We are throwing away some of
    // that randomness we just got but it should still have plenty of
    // randomness in it.
    //
    // This is a courtesy to the curious people who want to look at the
    // .dfterm3-cookie file. Instead of having random binary data that
    // might mess up their terminal, we have ASCII only.
    for ( int i1 = 0; i1 < 64; ++i1 ) {
        // The DELETE key (127) is not included nor are any of the control
        // characters or the space bar.
        random_bytes[i1] %= (127-33);
        random_bytes[i1] += 33;
    }

    magic_cookie_contents = string( (const char*) random_bytes, 64 );

    return true;
}

static bool flushClient( Dfterm3Client* client )
{
again:
    CActiveSocket* s = client->client_socket;
    int32_t received_bytes = s->Receive( 8192 );
    if ( received_bytes == -1 ) {
        CSimpleSocket::CSocketError err = s->GetSocketError();
        if ( err == CSimpleSocket::SocketInterrupted ) goto again;
        if ( err == CSimpleSocket::SocketEwouldblock ) {
            return true;
        }
        return false;
    } else if ( received_bytes == 0 ) {
        return false;
    }

    // received_bytes > 0

    client->incoming_message += string( (char*) s->GetData()
                                      , received_bytes );
    // We could repeat by jumping to again: label but that has a small risk
    // that we always receive more and more data and never get out.
    // goto again;
    return true;
}

static bool handleClientSocket( color_ostream &out, Dfterm3Client* client )
{
    if ( client->incoming_message_len > 10000 ) {
        return false;
    }
    if ( !client->handshake_complete ) {
        return sendHandshaking( out, client );
    }
    if ( !client->acknowledgement_complete ) {
        bool result = expectAcknowledgement( client, out );
        if ( result && client->acknowledgement_complete ) {
            out << "Dfterm3 has successfully connected to us." << endl;
        }
        return result;
    }

    if ( !flushClient( client ) ) {
        return false;
    }
    handleInput( client, out );

    return sendScreenData( out, client );
}

static SDL::Key mapInputCodeToSDL( const uint32_t code )
{
#define MAP(a, b) if ( code == (a) ) { return b; };
    MAP(65, SDL::K_a);
    MAP(66, SDL::K_b);
    MAP(67, SDL::K_c);
    MAP(68, SDL::K_d);
    MAP(69, SDL::K_e);
    MAP(70, SDL::K_f);
    MAP(71, SDL::K_g);
    MAP(72, SDL::K_h);
    MAP(73, SDL::K_i);
    MAP(74, SDL::K_j);
    MAP(75, SDL::K_k);
    MAP(76, SDL::K_l);
    MAP(77, SDL::K_m);
    MAP(78, SDL::K_n);
    MAP(79, SDL::K_o);
    MAP(80, SDL::K_p);
    MAP(81, SDL::K_q);
    MAP(82, SDL::K_r);
    MAP(83, SDL::K_s);
    MAP(84, SDL::K_t);
    MAP(85, SDL::K_u);
    MAP(86, SDL::K_v);
    MAP(87, SDL::K_w);
    MAP(88, SDL::K_x);
    MAP(89, SDL::K_y);
    MAP(90, SDL::K_z);

    MAP(48, SDL::K_0);
    MAP(49, SDL::K_1);
    MAP(50, SDL::K_2);
    MAP(51, SDL::K_3);
    MAP(52, SDL::K_4);
    MAP(53, SDL::K_5);
    MAP(54, SDL::K_6);
    MAP(55, SDL::K_7);
    MAP(56, SDL::K_8);
    MAP(57, SDL::K_9);

    MAP(32, SDL::K_SPACE);
    MAP(9, SDL::K_TAB);
    MAP(8, SDL::K_BACKSPACE);

    MAP(96, SDL::K_KP0);
    MAP(97, SDL::K_KP1);
    MAP(98, SDL::K_KP2);
    MAP(99, SDL::K_KP3);
    MAP(100, SDL::K_KP4);
    MAP(101, SDL::K_KP5);
    MAP(102, SDL::K_KP6);
    MAP(103, SDL::K_KP7);
    MAP(104, SDL::K_KP8);
    MAP(105, SDL::K_KP9);
    MAP(144, SDL::K_NUMLOCK);

    MAP(111, SDL::K_KP_DIVIDE);
    MAP(106, SDL::K_KP_MULTIPLY);
    MAP(109, SDL::K_KP_MINUS);
    MAP(107, SDL::K_KP_PLUS);

    MAP(33, SDL::K_PAGEUP);
    MAP(34, SDL::K_PAGEDOWN);
    MAP(35, SDL::K_END);
    MAP(36, SDL::K_HOME);
    MAP(46, SDL::K_DELETE);

    MAP(112, SDL::K_F1);
    MAP(113, SDL::K_F2);
    MAP(114, SDL::K_F3);
    MAP(115, SDL::K_F4);
    MAP(116, SDL::K_F5);
    MAP(117, SDL::K_F6);
    MAP(118, SDL::K_F7);
    MAP(119, SDL::K_F8);
    MAP(120, SDL::K_F9);
    MAP(121, SDL::K_F10);
    MAP(122, SDL::K_F11);
    MAP(123, SDL::K_F12);

    MAP(37, SDL::K_LEFT);
    MAP(39, SDL::K_RIGHT);
    MAP(38, SDL::K_UP);
    MAP(40, SDL::K_DOWN);

    MAP(188, SDL::K_LESS);
    MAP(190, SDL::K_GREATER);

    MAP(13, SDL::K_RETURN);
    MAP(16, SDL::K_LSHIFT);
    MAP(17, SDL::K_LCTRL);
    MAP(18, SDL::K_LALT);
    MAP(27, SDL::K_ESCAPE);
#undef MAP
    return SDL::K_UNKNOWN;
}

enum KeyDirection { Up = 0, Down = 1, UpAndDown = 2 };

static void handleInput( Dfterm3Client* client, color_ostream &out )
{
    while ( client->tryConsumeMessage() ) {
        // Key input?
        if ( client->consuming_message[0] == 1 ) {
            if ( client->consuming_message.size() < 13 ) {
                continue;
            }
            // The next update shall happen immediately when
            // possible. This should give the feeling that the
            // interface is slightly more responsive.
            last_time_updated = 0;

            uint32_t code;
            uint32_t code_point;

            // Using memcpy() makes sure wrong alignment doesn't do
            // anything bad.
            memcpy( &code
                  , &client->consuming_message.data()[1]
                  , sizeof(uint32_t) );
            memcpy( &code_point
                  , &client->consuming_message.data()[5]
                  , sizeof(uint32_t) );

            KeyDirection key_direction = (KeyDirection)
                client->consuming_message[9];
            bool shift_down = (bool) client->consuming_message[10];
            bool alt_down = (bool) client->consuming_message[11];
            bool ctrl_down = (bool) client->consuming_message[12];

            SDL::Event event;

            uint16_t mods = (uint16_t) SDL::KMOD_NONE;
            if ( shift_down ) mods |= SDL::KMOD_SHIFT;
            if ( alt_down ) mods |= SDL::KMOD_ALT;
            if ( ctrl_down ) mods |= SDL::KMOD_CTRL;
            SDL::Mod actual_mods = (SDL::Mod) mods;

            code_point = ntohl( code_point );

            SDL::Key key = mapInputCodeToSDL( ntohl( code ) );
            if ( key != SDL::K_UNKNOWN ) {

                if ( key_direction == Down || key_direction == UpAndDown ) {
                    memset( &event, 0, sizeof(event) );
                    event.type = SDL::ET_KEYDOWN;
                    event.key.state = SDL::BTN_PRESSED;
                    event.key.which = 0;
                    event.key.ksym.mod = actual_mods;
                    event.key.ksym.sym = key;
                    mySDL_PushEvent( &event );
                }

                if ( key_direction == Up || key_direction == UpAndDown ) {
                    memset( &event, 0, sizeof(event) );
                    event.type = SDL::ET_KEYUP;
                    event.key.state = SDL::BTN_RELEASED;
                    event.key.which = 0;
                    event.key.ksym.mod = actual_mods;
                    event.key.ksym.sym = key;
                    mySDL_PushEvent( &event );
                }
            } else if ( code_point ) {

                if ( key_direction == Down || key_direction == UpAndDown ) {
                    memset( &event, 0, sizeof(event) );
                    event.type = SDL::ET_KEYDOWN;
                    event.key.state = SDL::BTN_PRESSED;
                    event.key.which = 0;
                    event.key.ksym.mod = actual_mods;
                    event.key.ksym.unicode = (uint16_t) code_point;
                    mySDL_PushEvent( &event );
                }

                if ( key_direction == Up || key_direction == UpAndDown ) {
                    memset( &event, 0, sizeof(event) );
                    event.type = SDL::ET_KEYUP;
                    event.key.state = SDL::BTN_RELEASED;
                    event.key.which = 0;
                    event.key.ksym.mod = actual_mods;
                    event.key.ksym.unicode = (uint16_t) code_point;
                    mySDL_PushEvent( &event );
                }
            }
        }
    }
}

static bool sendScreenData( color_ostream &out, Dfterm3Client* client )
{
    const df::renderer* renderer = enabler->renderer;
    const uint8_t* screen = renderer->screen;

    auto dim = Screen::getWindowSize();
    int w = dim.x;
    int h = dim.y;
    if ( w < 0 || h < 0 ) return false;
    if ( w == 0 || h == 0) return true;

    uint8_t* sendings = (uint8_t*) calloc( w*h*2 + sizeof(int)*2, 1 );
    if ( !sendings ) {
        fprintf( stderr, "calloc() failed. Bad things could happen now.\n");
        return false;
    }
    uint8_t* bufs = &sendings[sizeof(int)*2];

    uint8_t* cp437 = bufs;
    uint8_t* colors = &bufs[w*h];

    for ( int x = 0; x < w; ++x ) {
        for ( int y = 0; y < h; ++y ) {
            cp437[x+y*w] = screen[(y+x*h)*4];
            colors[x+y*w] = (screen[(y+x*h)*4+1] << 4) |
                            screen[(y+x*h)*4+2];
            if ( screen[(y+x*h)*4+3] ) {
                colors[x+y*w] |= 0x80;
            }
        }
    }

    ((int*) sendings)[0] = htonl( w );
    ((int*) sendings)[1] = htonl( h );

    bool result = sendPrefixedData( client
                                  , sendings
                                  , w*h*2 + sizeof(int) * 2
                                  , DontUseProtobuf );
    free(sendings);
    return result;
}

static void initialize_SDL_PushEvent( void )
{
#ifndef _WIN32
    mySDL_PushEvent = SDL_PushEvent;
#else
    mySDL_PushEvent = (int (*)( SDL::Event* ))
                      GetProcAddress( GetModuleHandle("SDLreal.dll")
                                    , "SDL_PushEvent" );
#endif
}

