cmake_minimum_required (VERSION 3.0)

project(honoka)

set(LIBHONOKA_VERSION 20010019)
set(LIBHONOKA_VERSION_STRING "2.1.1")

option(HONOKAMIKU_V3_NOHDR_CHECK "Disable version 3 strict header checking (decrypt)" OFF)
option(HONOKAMIKU_BUILD_EXE "Build libhonoka command-line executable" ON)
option(HONOKAMIKU_BUILD_EXE_STANDALONE "Build executable statically (no *.so/*.dll)" OFF)

if(MSVC)
	# excuse me wtf
	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
	add_compile_definitions(_CRT_SECURE_NO_DEPRECATE)
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/honokamiku_config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/honokamiku_config.h")
include_directories("${PROJECT_BINARY_DIR}")
add_library(honoka SHARED md5.c honokamiku_decrypter.c)
add_library(honoka_static STATIC md5.c honokamiku_decrypter.c)
target_compile_definitions(honoka PUBLIC HONOKAMIKU_SHARED)

install(TARGETS honoka DESTINATION lib)
install(TARGETS honoka_static DESTINATION lib)
install(FILES honokamiku_decrypter.h DESTINATION include)

if(HONOKAMIKU_BUILD_EXE)
	add_executable(honoka2 honokamiku_program.c)
	if(HONOKAMIKU_BUILD_EXE_STANDALONE)
		target_link_libraries(honoka2 honoka_static)
		target_compile_definitions(honoka2 PRIVATE HONOKAMIKU_SHARED)
	else()
		target_link_libraries(honoka2 honoka)
	endif()
	
	install(TARGETS honoka2 DESTINATION bin)
endif()
