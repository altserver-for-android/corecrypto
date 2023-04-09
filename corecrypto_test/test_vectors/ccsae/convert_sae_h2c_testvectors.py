#!/usr/bin/python
# Copyright (c) (2020,2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

import os
import json
import binascii
import argparse

class Compiler(object):
    def __init__(self):
        self.syms = []
        self.decls = []
        self.symid = 0
        self.prefix = binascii.hexlify(os.urandom(6)).decode("utf-8")
        self.c_struct_data = ""
        self.test_vector_structs = []
        self.STRUCT = None

    def gen_sym(self, name):
        self.symid += 1
        return "cctest_{}_{}_{}".format(self.prefix, name, self.symid)

    def convert_hex_uint8t_list(self, name, data):
        try:
            _ = binascii.unhexlify(data) # Make sure it's hex
        except:
            try:
                data = "0" + data
                _ = binascii.unhexlify(data) # Make sure it's hex
            except:
                raise Exception(f"Is {name} really hex data ? {data}")
        data = ["0x{}".format(data[x:x+2]) for x in range(0, len(data), 2)]
        sym = self.gen_sym(name)
        self.c_struct_data += 'static const uint8_t {}[] = {{ {} }};\n'.format(sym, ', '.join(data))
        return (sym, len(data))

    def convert_struct(self, struct_name, name, data):
        sym = self.gen_sym(name)

        fields = []
        for k,v in data.items():
            fields.append('.{} = {}'.format(k, v))

        self.c_struct_data += 'static const struct {} {} = {{ {} }};\n'.format(
            self.STRUCT,
            sym,
            ', '.join(fields)
        )
        return sym


    def add_test_vector(self, name, data):
        assert self.STRUCT is not None
        
        sym = self.convert_struct(self.STRUCT, name, data)
        self.test_vector_structs.append("&{}".format(sym))
        return sym

    def finish_vectors(self, name):
        assert self.STRUCT is not None

        self.c_struct_data += 'static const struct {} *{}[] = {{ {} }};\n\n'.format(
            self.STRUCT,
            name,
            ', '.join(self.test_vector_structs)
        )
        return self.c_struct_data
    
class SAE_H2C(Compiler):
    '''
    struct sae_h2c_test_vector {
        unsigned tcId;
        unsigned curve;
        unsigned hkdf;
        const uint8_t *ssid;
        size_t ssid_len;
        const uint8_t *password;
        size_t password_len;
        const uint8_t *identifier;
        size_t identifier_len;
        const uint8_t *staA;
        size_t staA_len;
        const uint8_t *staB;
        size_t staB_len;
        const uint8_t *PT;
        size_t PT_len;
        const uint8_t PWE_x;
        size_t PWE_x_len;
        const uint8_t PWE_y;
        size_t PWE_y_len;
    };
    '''

    def __init__(self):
        super(SAE_H2C, self).__init__()
        self.STRUCT = "sae_h2c_test_vector"
        self.UINT8T_BLOBS = ["ssid", "password", "identifier", "staA", "staB", "PT", "PWE_x", "PWE_y"]

    def process(self, json_data):
        for test_group in json_data["testGroups"]:
            for test in test_group["tests"]:

                test_vector = {}

                for blob_name in self.UINT8T_BLOBS:
                    blob_value = test.get(blob_name, None)
                    if blob_value is not None:
                        sym, data_len = self.convert_hex_uint8t_list(blob_name, blob_value)
                        test_vector[blob_name] = sym
                        test_vector["{}_len".format(blob_name)] = data_len

                test_vector["tcId"] = test.get("tcId", -1)
                test_vector["curve"] = test_group.get("curve", -1)
                test_vector["hkdf"] = test_group.get("hkdf", -1)

                self.add_test_vector("test_vector", test_vector)

TEST_VECTORS = {
    "sae_h2c" : {
        "compiler": SAE_H2C,
        "files": ["ccsae/sae_h2c.json"],
        "output_dir": "ccsae/test_vectors",
        "test_vectors_name": "sae_h2c_vectors"
    }
}

def convert(srcroot):
    for test_name, test_struct in TEST_VECTORS.items():
        compiler = test_struct["compiler"]()
        input_files = list(map(lambda file: os.path.join(srcroot, "corecrypto_test/test_vectors", file), test_struct["files"]))
        output_file = os.path.join(srcroot, test_struct["output_dir"], '{}.kat'.format(test_name))
        print(output_file)

        with open(output_file, "w") as fout:
            for input_file in input_files:
                with open(input_file) as fin:
                    data = fin.read()
                    json_data = json.loads(data)
                    compiler.process(json_data)
            fout.write(compiler.finish_vectors(test_struct["test_vectors_name"]))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Convert Wycheproof test vectors into C structs")
    parser.add_argument("srcroot", help = "Repository srcroot")
    args = parser.parse_args()
    convert(args.srcroot)