import argparse
import os
from collections import Counter
import math
import json
from pathlib import Path
from tabulate import tabulate

parser = argparse.ArgumentParser(description="Tool to create entropy signatures and match a file with them")
parser.add_argument('input', type=str, help="Input file path")
parser.add_argument('--generate', action='store_true', help="Generate signatures from the given directory")
parser.add_argument('--chunk-size', type=int, default=2048, help="Size of the chunks")

def parseArgs():
    return parser.parse_args()

def calculateEntropy(data):
    byte_counts = Counter(data)

    total_bytes = len(data)

    entropy = 0
    for count in byte_counts.values():
        p_x = count / total_bytes
        entropy -= p_x * math.log2(p_x)

    return entropy


def displayMatchList(list):

    print("Found the following matches:")

    sorted_list = sorted(list, key=lambda x: x[1], reverse=True)

    formated_list = [[name, f"{value * 100:.3f}%"] for name, value in sorted_list]

    print(tabulate(formated_list))

def main():
    
    args = parseArgs()

    path = Path(args.input).resolve()

    if args.generate:

        if not path.is_dir():
            print("Input has to be a directory to create signatures")
        else:
            
            dirList = os.listdir(path)

            counter = 0

            for file in dirList:
                
                counter += 1

                signatureLength = 0
                signature = []

                with open(path / file, 'rb') as f:
                    byte_data = f.read()

                    total_bytes = len(byte_data)

                    fullEntropy = calculateEntropy(byte_data)

                    if fullEntropy > 7.5:
                        print("Skipped " + file + " because it's probably packed")
                    else:
                        numOfChunks = math.ceil(total_bytes / args.chunk_size)

                        f.seek(0)

                        for chunkIterator in range(numOfChunks):
                            chunk = f.read(args.chunk_size)
                            
                            if not chunk:
                                break

                            chunkEntropy = calculateEntropy(chunk)

                            signature.append(chunkEntropy) 

                        print(str(counter) + "/" + str(len(dirList)) + " : " + str(numOfChunks) + " chunks")

                        with open("signatures/" + file.split('.')[0] + ".json", 'w') as f2:
                            json.dump({
                                "name": file,
                                "length": total_bytes,
                                "signature": signature
                            }, f2)

    else:

        with open(path, "rb") as f:
            
            if not path.exists():
                print("The file doesn't exist") 
                return None
            if path.is_dir():
                print("Path can't be a directory")
                return None

            # --- Calculating test file entropy

            byte_data = f.read()

            total_bytes = len(byte_data)

            fullEntropy = calculateEntropy(byte_data)

            if fullEntropy > 7.5:
                print("File is probably packed and should therefore be treated with caution")
            else:
                
                f.seek(0)

                numOfChunks = math.ceil(total_bytes / args.chunk_size)

                testSignature = []

                for chunkIterator in range(numOfChunks):
                            chunk = f.read(args.chunk_size)
                            
                            if not chunk:
                                break

                            chunkEntropy = calculateEntropy(chunk)

                            testSignature.append(chunkEntropy)

                
                # --- Comparing with signatures ---
                
                dirList = os.listdir(os.getcwd() + "/signatures")

                counter = 0

                matchList = []

                for file in dirList:
                
                    with open("signatures/" + file, "r") as f2:

                        signatureData = json.load(f2)

                        signature = signatureData['signature']

                        numOfChunks = math.ceil(signatureData['length'] / args.chunk_size)

                        f2.seek(0)

                        cumulatedError = 0

                        maxLength = max(len(signature), len(testSignature))

                        for i in range(maxLength):

                            if len(signature) - 1 < i or len(testSignature) - 1 < i:
                                cumulatedError += 1
                            else:
                                cumulatedError += abs(testSignature[i] - signature[i]) / 8

                        match = 1 - (1 / maxLength) * cumulatedError
                        
                        matchList.append([
                            signatureData['name'],
                            match
                        ])
                
                displayMatchList(matchList)
    

if __name__ == "__main__":
    exit(main())