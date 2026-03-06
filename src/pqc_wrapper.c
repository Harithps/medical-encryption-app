#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>

// Kyber768 API
#include "api_kyber.h"

// Dilithium3 API
#include "api_dilithium.h"

/*
 * Kyber KEM Functions
 */

static PyObject* kyber_keypair(PyObject* self, PyObject* args) {
    uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    
    int ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    
    if (ret != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Kyber keypair generation failed");
        return NULL;
    }
    
    return Py_BuildValue("(y#y#)", 
                         pk, (Py_ssize_t)PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES,
                         sk, (Py_ssize_t)PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);
}

static PyObject* kyber_encapsulate(PyObject* self, PyObject* args) {
    const uint8_t* pk;
    Py_ssize_t pk_len;
    
    if (!PyArg_ParseTuple(args, "y#", &pk, &pk_len)) {
        return NULL;
    }
    
    if (pk_len != PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid public key length");
        return NULL;
    }
    
    uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    
    int ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
    
    if (ret != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Kyber encapsulation failed");
        return NULL;
    }
    
    return Py_BuildValue("(y#y#)",
                         ct, (Py_ssize_t)PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                         ss, (Py_ssize_t)PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES);
}

static PyObject* kyber_decapsulate(PyObject* self, PyObject* args) {
    const uint8_t* ct;
    const uint8_t* sk;
    Py_ssize_t ct_len, sk_len;
    
    if (!PyArg_ParseTuple(args, "y#y#", &ct, &ct_len, &sk, &sk_len)) {
        return NULL;
    }
    
    if (ct_len != PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid ciphertext length");
        return NULL;
    }
    
    if (sk_len != PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid secret key length");
        return NULL;
    }
    
    uint8_t ss[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    
    int ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
    
    if (ret != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Kyber decapsulation failed");
        return NULL;
    }
    
    return Py_BuildValue("y#", ss, (Py_ssize_t)PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES);
}

/*
 * Dilithium Signature Functions
 */

static PyObject* dilithium_keypair(PyObject* self, PyObject* args) {
    uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
    
    if (ret != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Dilithium keypair generation failed");
        return NULL;
    }
    
    return Py_BuildValue("(y#y#)",
                         pk, (Py_ssize_t)PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
                         sk, (Py_ssize_t)PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
}

static PyObject* dilithium_sign(PyObject* self, PyObject* args) {
    const uint8_t* msg;
    const uint8_t* sk;
    Py_ssize_t msg_len, sk_len;
    
    if (!PyArg_ParseTuple(args, "y#y#", &msg, &msg_len, &sk, &sk_len)) {
        return NULL;
    }
    
    if (sk_len != PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid secret key length");
        return NULL;
    }
    
    uint8_t* sig = (uint8_t*)malloc(msg_len + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES);
    if (!sig) {
        PyErr_NoMemory();
        return NULL;
    }
    
    size_t sig_len;
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign(sig, &sig_len, msg, msg_len, sk);
    
    if (ret != 0) {
        free(sig);
        PyErr_SetString(PyExc_RuntimeError, "Dilithium signing failed");
        return NULL;
    }
    
    PyObject* result = Py_BuildValue("y#", sig, (Py_ssize_t)sig_len);
    free(sig);
    
    return result;
}

static PyObject* dilithium_verify(PyObject* self, PyObject* args) {
    const uint8_t* sig;
    const uint8_t* pk;
    Py_ssize_t sig_len, pk_len;
    
    if (!PyArg_ParseTuple(args, "y#y#", &sig, &sig_len, &pk, &pk_len)) {
        return NULL;
    }
    
    if (pk_len != PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid public key length");
        return NULL;
    }
    
    uint8_t* msg = (uint8_t*)malloc(sig_len);
    if (!msg) {
        PyErr_NoMemory();
        return NULL;
    }
    
    size_t msg_len;
    int ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_open(msg, &msg_len, sig, sig_len, pk);
    
    if (ret != 0) {
        free(msg);
        Py_RETURN_FALSE;
    }
    
    PyObject* result = Py_BuildValue("y#", msg, (Py_ssize_t)msg_len);
    free(msg);
    
    return result;
}

/*
 * Utility Functions
 */

static PyObject* get_kyber_params(PyObject* self, PyObject* args) {
    return Py_BuildValue("{s:i,s:i,s:i,s:i}",
                         "public_key_bytes", PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES,
                         "secret_key_bytes", PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES,
                         "ciphertext_bytes", PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                         "shared_secret_bytes", PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES);
}

static PyObject* get_dilithium_params(PyObject* self, PyObject* args) {
    return Py_BuildValue("{s:i,s:i,s:i}",
                         "public_key_bytes", PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES,
                         "secret_key_bytes", PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES,
                         "signature_bytes", PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES);
}

/*
 * Method definitions
 */

static PyMethodDef PQCMethods[] = {
    // Kyber KEM
    {"kyber_keypair", kyber_keypair, METH_NOARGS, "Generate Kyber768 keypair"},
    {"kyber_encapsulate", kyber_encapsulate, METH_VARARGS, "Kyber768 encapsulation"},
    {"kyber_decapsulate", kyber_decapsulate, METH_VARARGS, "Kyber768 decapsulation"},
    
    // Dilithium Signatures
    {"dilithium_keypair", dilithium_keypair, METH_NOARGS, "Generate Dilithium3 keypair"},
    {"dilithium_sign", dilithium_sign, METH_VARARGS, "Sign message with Dilithium3"},
    {"dilithium_verify", dilithium_verify, METH_VARARGS, "Verify Dilithium3 signature"},
    
    // Utility
    {"get_kyber_params", get_kyber_params, METH_NOARGS, "Get Kyber768 parameters"},
    {"get_dilithium_params", get_dilithium_params, METH_NOARGS, "Get Dilithium3 parameters"},
    
    {NULL, NULL, 0, NULL}
};

/*
 * Module definition
 */

static struct PyModuleDef pqcmodule = {
    PyModuleDef_HEAD_INIT,
    "pqc_native",
    "Post-Quantum Cryptography with Kyber768 and Dilithium3",
    -1,
    PQCMethods
};

PyMODINIT_FUNC PyInit_pqc_native(void) {
    return PyModule_Create(&pqcmodule);
}