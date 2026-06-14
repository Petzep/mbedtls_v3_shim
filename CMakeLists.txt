if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER_EQUAL "6.0")
  idf_component_register(
    SRCS "src/pk_rsa.c"
         "src/pk_ec.c"
         "src/ecdh.c"
         "src/rsa_import_export.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES mbedtls
  )
else()
  idf_component_register()
endif()
