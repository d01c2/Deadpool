#!/usr/bin/env python
import os
import re
import sys
sys.path.insert(0, '../../')
from deadpool_dca import *

def processinput(iblock, blocksize):
    p='%0*x' % (2*blocksize, iblock)
    return (None, [p[j*2:(j+1)*2] for j in range(len(p)//2)])

def processoutput(output, blocksize):
    return int([o[8:] for o in output.split('\n') if "OUTPUT" in o][0].replace(" ", ""), 16)

typeIIM_masked = Filter('typeIIM_masked',
    ['R'], 
    lambda stack_range, addr, size, data: (
        data <= 255 and
        size == 1 and
        addr > 0x7ffffff36c00
    ),
    lambda addr, size, data: data & 0xFF,
    '<B')

typeIIM_mask = Filter('typeIIM_mask',
    ['R'],
    lambda stack_range, addr, size, data: (
        data <= 255 and
        size == 1 and
        addr > 0x7ffffff36c00
    ),
    lambda addr, size, data: data & 0xFF,
    '<B')

filters = [typeIIM_masked, typeIIM_mask]

T=TracerPIN('../target/WB_LEE_CASE1_Client', 
    processinput, 
    processoutput, 
    ARCH.amd64, 
    16, 
    filters=filters,
    debug=True)

T.run(256)

# Create second-order traces by combining masked data and mask
def combine_traces(dir_path):
    masked_files = [f for f in os.listdir(dir_path) if f.startswith('trace_typeIIM_masked_') and f.endswith('.bin')]
    
    for masked_file in masked_files:
        match = re.search(r'trace_typeIIM_masked_(\d+)_(.*?)\.bin', masked_file)
        if match:
            trace_id = match.group(1)
            postfix = match.group(2)
            mask_file = "trace_typeIIM_mask_%s_%s.bin" % (trace_id, postfix)
            mask_files = [f for f in os.listdir(dir_path) if f.startswith(mask_file.split('*')[0])]
            
            if mask_files:
                mask_file = mask_files[0]
                masked_path = os.path.join(dir_path, masked_file)
                mask_path = os.path.join(dir_path, mask_file)
                
                try:
                    with open(masked_path, 'rb') as f_masked, open(mask_path, 'rb') as f_mask:
                        masked_data = f_masked.read()
                        mask_data = f_mask.read()
                        
                        if len(masked_data) == len(mask_data):
                            # XOR operation for second-order trace
                            combined = bytearray([ord(a) ^ ord(b) for a, b in zip(masked_data, mask_data)])
                            
                            output_file = "trace_combined_%s_%s.bin" % (trace_id, postfix)
                            output_path = os.path.join(dir_path, output_file)
                            with open(output_path, 'wb') as f_out:
                                f_out.write(combined)
                            print("Created %s" % output_file)
                        else:
                            print("Skipping trace %s due to file size mismatch" % trace_id)
                except IOError as e:
                    print("Error processing trace %s: %s" % (trace_id, str(e)))
            else:
                print("Skipping trace %s due to missing mask file" % trace_id)
        else:
            print("Skipping file %s due to invalid filename format" % masked_file)

combine_traces(".")

combined = Filter('combined',
    ['R'],
    lambda stack_range, addr, size, data: (
        data <= 255 and
        size == 1 and
        addr > 0x7ffffff36c00
    ),
    lambda addr, size, data: data & 0xFF,
    '<B')

# Configuration for HODCA
configs = {
    'attack': {
        'algorithm':'AES',
        'position':'LUT/AES_AFTER_SBOX',
        'guess':'input',
        'bitnum':'all',
        'bytenum':'all',
        'threads':'8',
        'samples':'37368',
        'traces':'256'
    }
}

# Process traces and perform HODCA
bin2daredevil(
    keywords=[combined],
    configs=configs,
    delete_bin=False,
)