# Cluster Mapper Fixture test
target_add_unittest(dotdot_mapper NAME dotdot_cluster_mapper_fixt_test SOURCES
                    dotdot_cluster_mapper_fixt_test.c)

# Basic Cluster Mapper test
target_add_unittest(
  dotdot_mapper
  NAME
  basic_cluster_mapper_test
  SOURCES
  basic_cluster_mapper_test.cpp
  DEPENDS
  zpc_attribute_store_test_helper
  unify_dotdot_attribute_store
  zwave_definitions)

# OnOff Cluster Mapper test
target_add_unittest(
  dotdot_mapper
  NAME
  on_off_cluster_mapper_test
  SOURCES
  on_off_cluster_mapper_test.c
  DEPENDS
  zpc_attribute_store_test_helper
  unify_dotdot_attribute_store
  uic_dotdot_mqtt_mock
  zwave_network_management_mock)

# Binding Cluster Mapper Helper test
target_add_unittest(
  dotdot_mapper_binding_cluster_helper
  NAME
  binding_cluster_mapper_helper_test
  SOURCES
  binding_cluster_mapper_helper_test.c
  DEPENDS
  zpc_attribute_store_test_helper)

# Binding Cluster Mapper test
target_add_unittest(
  dotdot_mapper
  NAME
  binding_cluster_mapper_test
  SOURCES
  binding_cluster_mapper_test.c
  DEPENDS
  zpc_attribute_store_test_helper
  zwave_network_management_mock
  uic_dotdot_mqtt_mock)
if(${ZPC_BUILD_TESTING_PROPERTY_DISABLED})
  message(WARNING "Please fix this test")
  set_tests_properties(binding_cluster_mapper_test
    PROPERTIES DISABLED True)
endif()

