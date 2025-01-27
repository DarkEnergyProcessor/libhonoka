cmake_minimum_required (VERSION 3.0)

project(honoka)

set(LIBHONOKA_VERSION 20010019)
set(LIBHONOKA_VERSION_STRING "2.1.1")

if(POLICY CMP0077)
	# option() honor normal variables
	cmake_policy(SET CMP0077 NEW)
endif()

# If it's a subproject, don't build exe
get_directory_property(HONOKAMIKU_IN_SUBPROJECT PARENT_DIRECTORY)
if(HONOKAMIKU_IN_SUBPROJECT)
	set(HONOKAMIKU_BUILD_EXE_DEFAULT OFF)
	set(HONOKAMIKU_INSTALL_DEFAULT OFF)
else()
	set(HONOKAMIKU_BUILD_EXE_DEFAULT ON)
	set(HONOKAMIKU_INSTALL_DEFAULT ON)
endif()

option(HONOKAMIKU_V3_NOHDR_CHECK "Disable version 3 strict header checking (decrypt)" OFF)
option(HONOKAMIKU_BUILD_EXE "Build libhonoka command-line executable" ${HONOKAMIKU_BUILD_EXE_DEFAULT})
option(HONOKAMIKU_BUILD_EXE_STANDALONE "Build executable statically (no *.so/*.dll)" OFF)
option(HONOKAMIKU_INSTALL "Install executable, library, and header files" ${HONOKAMIKU_INSTALL_DEFAULT})

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/honokamiku_config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/honokamiku_config.h")
add_library(honoka SHARED md5.c honokamiku_decrypter.c)
add_library(honoka_static STATIC md5.c honokamiku_decrypter.c)
target_compile_definitions(honoka PUBLIC HONOKAMIKU_SHARED)

target_include_directories(honoka PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(honoka PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(honoka_static PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(honoka_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

if(MSVC)
	# excuse me wtf
	target_compile_definitions(honoka PRIVATE _CRT_SECURE_NO_WARNINGS)
	target_compile_definitions(honoka PRIVATE _CRT_SECURE_NO_DEPRECATE)
	target_compile_definitions(honoka_static PRIVATE _CRT_SECURE_NO_WARNINGS)
	target_compile_definitions(honoka_static PRIVATE _CRT_SECURE_NO_DEPRECATE)
endif()

if(HONOKAMIKU_INSTALL)
	install(TARGETS honoka DESTINATION lib RUNTIME DESTINATION bin)
	install(TARGETS honoka_static DESTINATION lib)
	install(FILES honokamiku_decrypter.h DESTINATION include)
endif()

if(HONOKAMIKU_BUILD_EXE)
	add_executable(honoka2 honokamiku_program.c)
	if(HONOKAMIKU_BUILD_EXE_STANDALONE)
		target_link_libraries(honoka2 honoka_static)
		target_compile_definitions(honoka2 PRIVATE HONOKAMIKU_SHARED)
	else()
		target_link_libraries(honoka2 honoka)
	endif()

	if(MSVC)
		# another excuse me wtf
		target_compile_definitions(honoka2 PRIVATE _CRT_SECURE_NO_WARNINGS)
		target_compile_definitions(honoka2 PRIVATE _CRT_SECURE_NO_DEPRECATE)
	endif()

	if(HONOKAMIKU_INSTALL)
		install(TARGETS honoka2 DESTINATION bin)
	endif()
endif()
