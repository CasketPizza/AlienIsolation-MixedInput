cmake_minimum_required(VERSION 3.20)
project(AlienIsolationMixedInput LANGUAGES CXX)

if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "Use MSVC and -A Win32 (x86 inline assembly required)")
endif()

function(add_mixed_input_variant target source output_directory)
  add_library(${target} SHARED ${source})
  target_compile_features(${target} PRIVATE cxx_std_17)
  target_compile_options(${target} PRIVATE /W4 /WX /O2 /GS /guard:cf)
  target_link_options(${target} PRIVATE /DYNAMICBASE /NXCOMPAT /guard:cf)
  target_link_libraries(${target} PRIVATE advapi32)
  set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
  set_target_properties(${target} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "AlienIsolation.MixedInput"
    SUFFIX ".asi"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${output_directory}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/${output_directory}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/${output_directory}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/${output_directory}"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/${output_directory}")
endfunction()

add_mixed_input_variant(MixedInputController
  src/MixedInputControllerPrompts.cpp controller-prompts)
add_mixed_input_variant(MixedInputKBM
  src/MixedInputKBMPrompts.cpp kbm-prompts)
