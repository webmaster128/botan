project(Botan)
cmake_minimum_required(VERSION 2.8)

# Configure for use with CMake
#
#   ./configure.py --with-bzip2 --with-zlib --with-lzma --enable-modules="dyn_load"
#

macro(use_cxx11)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_CXX_FLAGS "--std=gnu++11 ${CMAKE_CXX_FLAGS}")
    endif ()
  else ()
    set (CMAKE_CXX_STANDARD 11)
  endif ()
endmacro(use_cxx11)

use_cxx11()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wformat=2 -Wlogical-op -Wmissing-include-dirs -Wnon-virtual-dtor -Woverloaded-virtual -Wswitch-default -Wuninitialized")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/src/cmake")

# Includes. Where ./configure.py puts them
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/build/include")
include_directories(${INCLUDE_DIR})

# libbotan
set(BOTAN_SRC
    src/lib/asn1/alg_id.cpp
    src/lib/asn1/asn1_alt_name.cpp
    src/lib/asn1/asn1_attribute.cpp
    src/lib/asn1/asn1_obj.cpp
    src/lib/asn1/asn1_oid.cpp
    src/lib/asn1/asn1_str.cpp
    src/lib/asn1/asn1_time.cpp
    src/lib/asn1/ber_dec.cpp
    src/lib/asn1/der_enc.cpp
    src/lib/asn1/oid_lookup/default.cpp
    src/lib/asn1/oid_lookup/oids.cpp
    src/lib/asn1/x509_dn.cpp
    src/lib/base/init.cpp
    src/lib/base/scan_name.cpp
    src/lib/base/symkey.cpp
    src/lib/base/transform.cpp
    src/lib/block/block_cipher.cpp
    src/lib/block/aes/aes.cpp
    src/lib/block/aes_ni/aes_ni.cpp
    src/lib/block/aes_ssse3/aes_ssse3.cpp
    src/lib/block/blowfish/blfs_tab.cpp
    src/lib/block/blowfish/blowfish.cpp
    src/lib/block/camellia/camellia.cpp
    src/lib/block/cascade/cascade.cpp
    src/lib/block/cast/cast128.cpp
    src/lib/block/cast/cast256.cpp
    src/lib/block/des/des.cpp
    src/lib/block/des/des_tab.cpp
    src/lib/block/des/desx.cpp
    src/lib/block/gost_28147/gost_28147.cpp
    src/lib/block/idea/idea.cpp
    src/lib/block/idea_sse2/idea_sse2.cpp
    src/lib/block/kasumi/kasumi.cpp
    src/lib/block/lion/lion.cpp
    src/lib/block/mars/mars.cpp
    src/lib/block/misty1/misty1.cpp
    src/lib/block/noekeon/noekeon.cpp
    src/lib/block/noekeon_simd/noekeon_simd.cpp
    src/lib/block/rc2/rc2.cpp
    src/lib/block/rc5/rc5.cpp
    src/lib/block/rc6/rc6.cpp
    src/lib/block/safer/safer_sk.cpp
    src/lib/block/seed/seed.cpp
    src/lib/block/seed/seed_tab.cpp
    src/lib/block/serpent/serpent.cpp
    src/lib/block/serpent_simd/serp_simd.cpp
    src/lib/block/tea/tea.cpp
    src/lib/block/threefish_avx2/threefish_avx2.cpp
    src/lib/block/threefish/threefish.cpp
    src/lib/block/twofish/twofish.cpp
    src/lib/block/twofish/two_tab.cpp
    src/lib/block/xtea_simd/xtea_simd.cpp
    src/lib/block/xtea/xtea.cpp
    src/lib/cert/x509/certstor.cpp
    src/lib/cert/x509/crl_ent.cpp
    src/lib/cert/x509/key_constraint.cpp
    src/lib/cert/x509/ocsp.cpp
    src/lib/cert/x509/ocsp_types.cpp
    src/lib/cert/x509/pkcs10.cpp
    src/lib/cert/x509/x509_ca.cpp
    src/lib/cert/x509/x509cert.cpp
    src/lib/cert/x509/x509_crl.cpp
    src/lib/cert/x509/x509_ext.cpp
    src/lib/cert/x509/x509_obj.cpp
    src/lib/cert/x509/x509opt.cpp
    src/lib/cert/x509/x509path.cpp
    src/lib/cert/x509/x509self.cpp
    src/lib/codec/base64/base64.cpp
    src/lib/codec/hex/hex.cpp
    src/lib/compression/compression.cpp
    src/lib/entropy/dev_random/dev_random.cpp
    src/lib/entropy/egd/es_egd.cpp
    src/lib/entropy/entropy_srcs.cpp
    src/lib/entropy/hres_timer/hres_timer.cpp
    src/lib/entropy/proc_walk/proc_walk.cpp
    src/lib/entropy/rdrand/rdrand.cpp
    src/lib/entropy/rdseed/rdseed.cpp
    src/lib/entropy/unix_procs/unix_procs.cpp
    src/lib/entropy/unix_procs/unix_proc_sources.cpp
    src/lib/ffi/ffi.cpp
    src/lib/filters/algo_filt.cpp
    src/lib/filters/basefilt.cpp
    src/lib/filters/buf_filt.cpp
    src/lib/filters/codec_filt/b64_filt.cpp
    src/lib/filters/codec_filt/hex_filt.cpp
    src/lib/filters/comp_filter.cpp
    src/lib/filters/data_snk.cpp
    src/lib/filters/fd_unix/fd_unix.cpp
    src/lib/filters/filter.cpp
    src/lib/filters/key_filt.cpp
    src/lib/filters/out_buf.cpp
    src/lib/filters/pipe.cpp
    src/lib/filters/pipe_io.cpp
    src/lib/filters/pipe_rw.cpp
    src/lib/filters/secqueue.cpp
    src/lib/filters/threaded_fork.cpp
    src/lib/filters/transform_filter.cpp
    src/lib/hash/checksum/adler32/adler32.cpp
    src/lib/hash/checksum/crc24/crc24.cpp
    src/lib/hash/checksum/crc32/crc32.cpp
    src/lib/hash/comb4p/comb4p.cpp
    src/lib/hash/gost_3411/gost_3411.cpp
    src/lib/hash/has160/has160.cpp
    src/lib/hash/hash.cpp
    src/lib/hash/keccak/keccak.cpp
    src/lib/hash/md2/md2.cpp
    src/lib/hash/md4/md4.cpp
    src/lib/hash/md5/md5.cpp
    src/lib/hash/mdx_hash/mdx_hash.cpp
    src/lib/hash/par_hash/par_hash.cpp
    src/lib/hash/rmd128/rmd128.cpp
    src/lib/hash/rmd160/rmd160.cpp
    src/lib/hash/sha1/sha160.cpp
    src/lib/hash/sha1_sse2/sha1_sse2.cpp
    src/lib/hash/sha2_32/sha2_32.cpp
    src/lib/hash/sha2_64/sha2_64.cpp
    src/lib/hash/skein/skein_512.cpp
    src/lib/hash/tiger/tiger.cpp
    src/lib/hash/tiger/tig_tab.cpp
    src/lib/hash/whirlpool/whirlpool.cpp
    src/lib/hash/whirlpool/whrl_tab.cpp
    src/lib/kdf/hkdf/hkdf.cpp
    src/lib/kdf/kdf1/kdf1.cpp
    src/lib/kdf/kdf2/kdf2.cpp
    src/lib/kdf/kdf.cpp
    src/lib/kdf/prf_tls/prf_tls.cpp
    src/lib/kdf/prf_x942/prf_x942.cpp
    src/lib/mac/cbc_mac/cbc_mac.cpp
    src/lib/mac/cmac/cmac.cpp
    src/lib/mac/hmac/hmac.cpp
    src/lib/mac/mac.cpp
    src/lib/mac/poly1305/poly1305.cpp
    src/lib/mac/siphash/siphash.cpp
    src/lib/mac/x919_mac/x919_mac.cpp
    src/lib/math/bigint/big_code.cpp
    src/lib/math/bigint/bigint.cpp
    src/lib/math/bigint/big_io.cpp
    src/lib/math/bigint/big_ops2.cpp
    src/lib/math/bigint/big_ops3.cpp
    src/lib/math/bigint/big_rand.cpp
    src/lib/math/bigint/divide.cpp
    src/lib/math/ec_gfp/curve_gfp.cpp
    src/lib/math/ec_gfp/curve_nistp.cpp
    src/lib/math/ec_gfp/point_gfp.cpp
    src/lib/math/mp/mp_asm.cpp
    src/lib/math/mp/mp_comba.cpp
    src/lib/math/mp/mp_karat.cpp
    src/lib/math/mp/mp_misc.cpp
    src/lib/math/mp/mp_monty.cpp
    src/lib/math/mp/mp_shift.cpp
    src/lib/math/numbertheory/dsa_gen.cpp
    src/lib/math/numbertheory/jacobi.cpp
    src/lib/math/numbertheory/make_prm.cpp
    src/lib/math/numbertheory/mp_numth.cpp
    src/lib/math/numbertheory/numthry.cpp
    src/lib/math/numbertheory/powm_fw.cpp
    src/lib/math/numbertheory/powm_mnt.cpp
    src/lib/math/numbertheory/pow_mod.cpp
    src/lib/math/numbertheory/primes.cpp
    src/lib/math/numbertheory/reducer.cpp
    src/lib/math/numbertheory/ressol.cpp
    src/lib/misc/aont/package.cpp
    src/lib/misc/cryptobox/cryptobox.cpp
    src/lib/misc/fpe_fe1/fpe_fe1.cpp
    src/lib/misc/openpgp/openpgp.cpp
    src/lib/misc/pbes2/pbes2.cpp
    src/lib/misc/pem/pem.cpp
    src/lib/misc/rfc3394/rfc3394.cpp
    src/lib/misc/srp6/srp6.cpp
    src/lib/misc/srp6/srp6_files.cpp
    src/lib/misc/tss/tss.cpp
    src/lib/modes/aead/aead.cpp
    src/lib/modes/aead/ccm/ccm.cpp
    src/lib/modes/aead/chacha20poly1305/chacha20poly1305.cpp
    src/lib/modes/aead/eax/eax.cpp
    src/lib/modes/aead/gcm/clmul/clmul.cpp
    src/lib/modes/aead/gcm/gcm.cpp
    src/lib/modes/aead/ocb/ocb.cpp
    src/lib/modes/aead/siv/siv.cpp
    src/lib/modes/cbc/cbc.cpp
    src/lib/modes/cfb/cfb.cpp
    src/lib/modes/cipher_mode.cpp
    src/lib/modes/ecb/ecb.cpp
    src/lib/modes/mode_pad/mode_pad.cpp
    src/lib/modes/xts/xts.cpp
    src/lib/passhash/bcrypt/bcrypt.cpp
    src/lib/passhash/passhash9/passhash9.cpp
    src/lib/pbkdf/pbkdf1/pbkdf1.cpp
    src/lib/pbkdf/pbkdf2/pbkdf2.cpp
    src/lib/pbkdf/pbkdf.cpp
    src/lib/pk_pad/eme.cpp
    src/lib/pk_pad/eme_oaep/oaep.cpp
    src/lib/pk_pad/eme_pkcs1/eme_pkcs.cpp
    src/lib/pk_pad/eme_raw/eme_raw.cpp
    src/lib/pk_pad/emsa.cpp
    src/lib/pk_pad/emsa1_bsi/emsa1_bsi.cpp
    src/lib/pk_pad/emsa1/emsa1.cpp
    src/lib/pk_pad/emsa_pkcs1/emsa_pkcs1.cpp
    src/lib/pk_pad/emsa_pssr/pssr.cpp
    src/lib/pk_pad/emsa_raw/emsa_raw.cpp
    src/lib/pk_pad/emsa_x931/emsa_x931.cpp
    src/lib/pk_pad/hash_id/hash_id.cpp
    src/lib/pk_pad/mgf1/mgf1.cpp
    src/lib/pubkey/blinding.cpp
    src/lib/pubkey/curve25519/curve25519.cpp
    src/lib/pubkey/curve25519/donna.cpp
    src/lib/pubkey/dh/dh.cpp
    src/lib/pubkey/dl_algo/dl_algo.cpp
    src/lib/pubkey/dl_group/dl_group.cpp
    src/lib/pubkey/dl_group/named.cpp
    src/lib/pubkey/dlies/dlies.cpp
    src/lib/pubkey/dsa/dsa.cpp
    src/lib/pubkey/ecc_key/ecc_key.cpp
    src/lib/pubkey/ecdh/ecdh.cpp
    src/lib/pubkey/ecdsa/ecdsa.cpp
    src/lib/pubkey/ec_group/ec_group.cpp
    src/lib/pubkey/ec_group/named.cpp
    src/lib/pubkey/elgamal/elgamal.cpp
    src/lib/pubkey/gost_3410/gost_3410.cpp
    src/lib/pubkey/if_algo/if_algo.cpp
    src/lib/pubkey/keypair/keypair.cpp
    src/lib/pubkey/mce/code_based_key_gen.cpp
    src/lib/pubkey/mce/gf2m_rootfind_dcmp.cpp
    src/lib/pubkey/mce/gf2m_small_m.cpp
    src/lib/pubkey/mce/goppa_code.cpp
    src/lib/pubkey/mceies/mceies.cpp
    src/lib/pubkey/mce/mce_kem.cpp
    src/lib/pubkey/mce/mceliece.cpp
    src/lib/pubkey/mce/mceliece_key.cpp
    src/lib/pubkey/mce/polyn_gf2m.cpp
    src/lib/pubkey/mce/workfactor.cpp
    src/lib/pubkey/nr/nr.cpp
    src/lib/pubkey/pk_algs.cpp
    src/lib/pubkey/pkcs8.cpp
    src/lib/pubkey/pk_keys.cpp
    src/lib/pubkey/pk_ops.cpp
    src/lib/pubkey/pubkey.cpp
    src/lib/pubkey/rfc6979/rfc6979.cpp
    src/lib/pubkey/rsa/rsa.cpp
    src/lib/pubkey/rw/rw.cpp
    src/lib/pubkey/workfactor.cpp
    src/lib/pubkey/x509_key.cpp
    src/lib/rng/hmac_drbg/hmac_drbg.cpp
    src/lib/rng/hmac_rng/hmac_rng.cpp
    src/lib/rng/rng.cpp
    src/lib/rng/system_rng/system_rng.cpp
    src/lib/rng/x931_rng/x931_rng.cpp
    src/lib/stream/chacha/chacha.cpp
    src/lib/stream/ctr/ctr.cpp
    src/lib/stream/ofb/ofb.cpp
    src/lib/stream/rc4/rc4.cpp
    src/lib/stream/salsa20/salsa20.cpp
    src/lib/stream/stream_cipher.cpp
    src/lib/tls/credentials_manager.cpp
    src/lib/tls/msg_certificate.cpp
    src/lib/tls/msg_cert_req.cpp
    src/lib/tls/msg_cert_verify.cpp
    src/lib/tls/msg_client_hello.cpp
    src/lib/tls/msg_client_kex.cpp
    src/lib/tls/msg_finished.cpp
    src/lib/tls/msg_hello_verify.cpp
    src/lib/tls/msg_server_hello.cpp
    src/lib/tls/msg_server_kex.cpp
    src/lib/tls/msg_session_ticket.cpp
    src/lib/tls/tls_alert.cpp
    src/lib/tls/tls_blocking.cpp
    src/lib/tls/tls_channel.cpp
    src/lib/tls/tls_ciphersuite.cpp
    src/lib/tls/tls_client.cpp
    src/lib/tls/tls_extensions.cpp
    src/lib/tls/tls_handshake_hash.cpp
    src/lib/tls/tls_handshake_io.cpp
    src/lib/tls/tls_handshake_state.cpp
    src/lib/tls/tls_heartbeats.cpp
    src/lib/tls/tls_policy.cpp
    src/lib/tls/tls_record.cpp
    src/lib/tls/tls_server.cpp
    src/lib/tls/tls_session.cpp
    src/lib/tls/tls_session_key.cpp
    src/lib/tls/tls_session_manager_memory.cpp
    src/lib/tls/tls_suite_info.cpp
    src/lib/tls/tls_version.cpp
    src/lib/utils/assert.cpp
    src/lib/utils/calendar.cpp
    src/lib/utils/charset.cpp
    src/lib/utils/cpuid.cpp
    src/lib/utils/data_src.cpp
    src/lib/utils/datastor/datastor.cpp
    src/lib/utils/dyn_load/dyn_load.cpp
    src/lib/utils/filesystem.cpp
    src/lib/utils/http_util/http_util.cpp
    src/lib/utils/locking_allocator/locking_allocator.cpp
    src/lib/utils/os_utils.cpp
    src/lib/utils/parsing.cpp
    src/lib/utils/read_cfg.cpp
    src/lib/utils/semaphore.cpp
    # src/lib/utils/sqlite3/sqlite3.cpp
    src/lib/utils/version.cpp
    src/lib/utils/zero_mem.cpp
)

# add a new target to show help for options that we add
# use add_custom_command(TARGET Botan-help ...) to extend the help text
add_custom_target(Botan-help)

# AVX2
set_source_files_properties(src/lib/block/threefish_avx2/threefish_avx2.cpp PROPERTIES COMPILE_FLAGS "-mavx2")
# SSSE3
set_source_files_properties(src/lib/block/aes_ssse3/aes_ssse3.cpp PROPERTIES COMPILE_FLAGS "-mssse3")
# AES-NI
set_source_files_properties(src/lib/block/aes_ni/aes_ni.cpp        PROPERTIES COMPILE_FLAGS "-maes -mpclmul -mssse3")
set_source_files_properties(src/lib/modes/aead/gcm/clmul/clmul.cpp PROPERTIES COMPILE_FLAGS "-maes -mpclmul -mssse3")

if ( WITH_LZMA )
    find_package( LZMA )
    if ( LZMA_FOUND )
        include_directories(${LZMA_INCLUDE_DIR})
        set(BOTAN_LIBRARIES ${BOTAN_LIBRARIES} ${LZMA_LIBRARIES})
        set(BOTAN_SRC ${BOTAN_SRC}
            compression/lzma/lzma.cpp)
    endif( LZMA_FOUND )
endif ( WITH_LZMA )
add_custom_command(TARGET Botan-help
    COMMAND echo "  To build with lzma support use: cmake -DWITH_LZMA=1")

if ( WITH_BZIP2 )
    find_package( BZip2 )
    if ( BZIP2_FOUND )
        include_directories(${BZIP_INCLUDE_DIRS})
        set(BOTAN_LIBRARIES ${BOTAN_LIBRARIES} ${BZIP2_LIBRARIES})
        set(BOTAN_SRC ${BOTAN_SRC}
            compression/bzip2/bzip2.cpp)
    endif( BZIP2_FOUND )
endif ( WITH_BZIP2 )
add_custom_command(TARGET Botan-help
    COMMAND echo "  To build with bzip2 support use: cmake -DWITH_BZIP2=1")

if ( WITH_ZLIB )
    find_package( ZLIB )
    if ( ZLIB_FOUND )
        include_directories(${ZLIB_INCLUDE_DIRS})
        set(BOTAN_LIBRARIES ${BOTAN_LIBRARIES} ${ZLIB_LIBRARIES})
        set(BOTAN_SRC ${BOTAN_SRC}
            compression/zlib/zlib.cpp)
    endif( ZLIB_FOUND )
endif ( WITH_ZLIB )
add_custom_command(TARGET Botan-help
    COMMAND echo "  To build with zlib support use: cmake -DWITH_ZLIB=1")

# set(Boost_DEBUG ON)
find_package(Boost COMPONENTS system filesystem REQUIRED)
set(BOTAN_LIBRARIES ${BOTAN_LIBRARIES} boost_filesystem)
set(BOTAN_LIBRARIES ${BOTAN_LIBRARIES} boost_system)

set(extra_link_libraries_lib)
if(NOT WIN32)
    list(APPEND extra_link_libraries_lib
                rt dl pthread)
endif()

set(CMAKE_DEBUG_POSTFIX "d")

if (NOT LIB_TYPE)
    set(LIB_TYPE STATIC)
endif()

add_custom_command(TARGET Botan-help
    COMMAND echo "  To build a static or shared Botan library use: cmake -DLIB_TYPE=STATIC or -DLIB_TYPE=SHARED")

message(STATUS "Building with LIB_TYPE=${LIB_TYPE}")
add_library(botan ${LIB_TYPE} ${BOTAN_SRC})

target_link_libraries(botan
                      ${BOTAN_LIBRARIES}
                      ${extra_link_libraries_lib})

file(GLOB include_install_files "${INCLUDE_DIR}/botan/*.h")
foreach (include_install_file ${include_install_files})
    get_filename_component(full_include_install_file ${include_install_file} REALPATH)
    install(FILES ${full_include_install_file} DESTINATION "include/botan-1.11/botan/")
endforeach (include_install_file ${include_instal_files})
install(TARGETS botan ARCHIVE DESTINATION "lib/botan")

# cli
add_executable(botan-cli
    src/cli/asn1.cpp
    src/cli/bench.cpp
    src/cli/cc_enc.cpp
    src/cli/compress.cpp
    src/cli/main.cpp
    src/cli/math.cpp
    src/cli/pubkey.cpp
    src/cli/tls_client.cpp
    src/cli/tls_proxy.cpp
    src/cli/tls_server.cpp
    src/cli/utils.cpp
    src/cli/x509.cpp
)

target_link_libraries(botan-cli
                      botan
                      ${extra_link_libraries_cli})

# tests
add_executable(botan-tests
    src/tests/main.cpp
    src/tests/test_aead.cpp
    src/tests/test_bigint.cpp
    src/tests/test_block.cpp
    src/tests/test_c25519.cpp
    src/tests/test_compression.cpp
    src/tests/test_cryptobox.cpp
    src/tests/test_cvc.cpp
    src/tests/test_dh.cpp
    src/tests/test_dlies.cpp
    src/tests/test_dsa.cpp
    src/tests/test_ecc_pointmul.cpp
    src/tests/test_ecdsa.cpp
    src/tests/test_elg.cpp
    src/tests/test_entropy.cpp
    src/tests/test_ffi.cpp
    src/tests/test_fuzzer.cpp
    src/tests/test_gf2m.cpp
    src/tests/test_gost_3410.cpp
    src/tests/test_hash.cpp
    src/tests/test_kdf.cpp
    src/tests/test_keywrap.cpp
    src/tests/test_mac.cpp
    src/tests/test_mceliece.cpp
    src/tests/test_modes.cpp
    src/tests/test_nr.cpp
    src/tests/test_ocb.cpp
    src/tests/test_passhash.cpp
    src/tests/test_pbkdf.cpp
    src/tests/test_pubkey.cpp
    src/tests/test_rfc6979.cpp
    src/tests/test_rng.cpp
    src/tests/test_rsa.cpp
    src/tests/test_rw.cpp
    src/tests/tests.cpp
    src/tests/test_srp6.cpp
    src/tests/test_stream.cpp
    src/tests/test_tss.cpp
    src/tests/test_utils.cpp
    src/tests/test_x509_path.cpp
    src/tests/unit_ecc.cpp
    src/tests/unit_ecdh.cpp
    src/tests/unit_ecdsa.cpp
    src/tests/unit_tls.cpp
    src/tests/unit_x509.cpp
)

target_link_libraries(botan-tests
                      botan
                      ${extra_link_libraries_tests})

add_dependencies(botan-tests botan)

