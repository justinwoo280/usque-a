add_executable(test_duration test_duration.cpp)
target_link_libraries(test_duration PRIVATE usque-a)
add_test(NAME duration COMMAND test_duration)
set_tests_properties(duration PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_config test_config.cpp)
target_link_libraries(test_config PRIVATE usque-a)
add_test(NAME config COMMAND test_config ${CMAKE_CURRENT_SOURCE_DIR}/testdata)

add_executable(test_validate test_validate.cpp)
target_link_libraries(test_validate PRIVATE usque-a)
add_test(NAME validate COMMAND test_validate)
set_tests_properties(validate PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_connectip test_connectip.c)
target_link_libraries(test_connectip PRIVATE usque-a)
add_test(NAME connectip COMMAND test_connectip)

add_executable(test_dns_hijack test_dns_hijack.c)
target_include_directories(test_dns_hijack PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_dns_hijack PRIVATE usque-a)
add_test(NAME dns_hijack COMMAND test_dns_hijack)

add_executable(test_fuzz test_fuzz.c)
target_link_libraries(test_fuzz PRIVATE usque-a)
add_test(NAME fuzz COMMAND test_fuzz)

add_executable(test_register test_register.c)
add_test(NAME register COMMAND test_register)

add_executable(test_regression test_regression.c)
target_link_libraries(test_regression PRIVATE usque-a)
add_test(NAME regression COMMAND test_regression)
