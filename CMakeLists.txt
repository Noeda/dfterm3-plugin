PROJECT (dfterm3-plugin)

MESSAGE(STATUS ${CMAKE_CURRENT_SOURCE_DIR})

ADD_CUSTOM_COMMAND(
    OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/proto/dfterm3.pb.cc"
           "${CMAKE_CURRENT_SOURCE_DIR}/proto/dfterm3.pb.h"
    COMMAND protoc-bin -I=${CMAKE_CURRENT_SOURCE_DIR}/proto/
                       --cpp_out=${CMAKE_CURRENT_SOURCE_DIR}/proto/
                       ${CMAKE_CURRENT_SOURCE_DIR}/proto/dfterm3.proto
    DEPENDS protoc-bin proto/dfterm3.proto)

SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_SOURCE_DIR}/proto/dfterm3.pb.cc PROPERTIES GENERATED 1)
SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_SOURCE_DIR}/proto/dfterm3.pb.h PROPERTIES GENERATED 1)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/proto)

DFHACK_PLUGIN(dfterm3 dfterm3.cpp dfterm3_strerror.cpp
                      proto/dfterm3.pb.cc
                      LINK_LIBRARIES clsocket)
