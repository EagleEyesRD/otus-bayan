cmake_minimum_required(VERSION 3.5)
project(bayan  VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})

if (MSVC)
set(Z_VCPKG_TARGET_TRIPLET_ARCH x86)
endif()

if(CMAKE_TOOLCHAIN_FILE)
    include(${CMAKE_TOOLCHAIN_FILE})
endif(CMAKE_TOOLCHAIN_FILE)

if (MSVC)
	set(Boost_ARCHITECTURE_TAG "-x86")
	set(Boost_USE_STATIC_LIBS ON)
	set(Boost_DEBUG ON)
endif()
find_package(Boost REQUIRED COMPONENTS program_options )
include_directories(${Boost_INCLUDE_DIR})

add_executable(bayan main.cpp)

target_link_libraries(program_options ${BOOST_LIBRARYDIR}) 


if (MSVC)
    target_compile_options(bayan PRIVATE
        /W4
    )
else ()
    target_compile_options(bayan PRIVATE
        -Wall -Wextra -pedantic -Werror
    )
endif()



install(TARGETS bayan RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT markessm@yandex.ru)

include(CPack)
