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
parser.add_argument('--family', action='store_true', help="Calculates the average signature over the files in the directory")
parser.add_argument('--collection', action='store_true', help="Store signatures individually but as one family")
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

    print("\n")

    print("Found the following individual matches:")

    individualList = [item for item in list if not item[0]]

    sorted_list = sorted(individualList, key=lambda x: x[2], reverse=True)

    formated_list = [[name, f"{value * 100:.2f}%"] for discard, name, value in sorted_list]
    print(tabulate(formated_list, headers=["Name", "Match"]))

    print("\n")

    print("Found the following collection matches:")

    collectionList = [item for item in list if item[0]]    

    sorted_list = sorted(collectionList, key=lambda x: x[2], reverse=True)

    formated_list = [[name, f"{value * 100:.2f}%", numMatches, f"{maxMatch * 100:.2f}%"] for discard, name, value, numMatches, maxMatch in sorted_list]
    print(tabulate(formated_list, headers=["Collection name", "Cumulated match", "Matches >85%", "Highest match"]))

    print("\n")

def main():
    
    args = parseArgs()

    path = Path(args.input).resolve()

    if args.generate:

        if not path.is_dir():
            print("Input has to be a directory to create signatures")
        else:
            
            dirList = os.listdir(path)

            counter = 0

            if not args.family:

                if args.collection:
                    signatureCollection = []

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

                            if not args.collection:

                                os.makedirs('signatures/', exist_ok=True)

                                with open("signatures/" + file.split('.')[0] + ".json", 'w') as f2:
                                    json.dump({
                                        "name": file,
                                        "max-length": numOfChunks,
                                        "collection": False,
                                        "chunk-size": args.chunk_size,
                                        "signature": signature,
                                        "usedFiles": file
                                    }, f2)

                            else:
                                signatureCollection.append(signature)

                if args.collection:

                    os.makedirs('signatures/', exist_ok=True)

                    with open("signatures/" + path.name + ".json", 'w') as f2:
                        json.dump({
                            "name": path.name,
                            "max-length": max([len(sig) for sig in signatureCollection]),
                            "chunk-size": args.chunk_size,
                            "collection": True,
                            "signature": signatureCollection,
                            "usedFiles": dirList
                        }, f2)

            else:

                signatures = []
                longestChunkLength = 0

                for file in dirList:
                    
                    counter += 1

                    signatureLength = 0
                    signature = []

                    with open(path / file, 'rb') as f:
                        byte_data = f.read()

                        total_bytes = len(byte_data)
                        
                        fullEntropy = calculateEntropy(byte_data)

                        if fullEntropy > 7.8:
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

                            longestChunkLength = max(longestChunkLength, numOfChunks)

                            signatures.append(signature)

                maxLen = max([len(list) for list in signatures])

                averageSignature = []

                for i in range(maxLen):

                    sum = 0

                    for sig in signatures:
                        
                        if not i > len(sig) - 1:
                            sum += sig[i]
                        
                    averageSignature.append(sum / len(signatures))

                os.makedirs('signatures/', exist_ok=True)

                with open("signatures/" + path.name + ".json", 'w') as f2:
                    json.dump({
                        "name": path.name,
                        "max-length": longestChunkLength,
                        "collection": False,
                        "chunk-size": args.chunk_size,
                        "signature": averageSignature,
                        "usedFiles": dirList
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

            if fullEntropy > 7.8:
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

                        if not signatureData['chunk-size'] == args.chunk_size:
                            print("Signature has the chunk size " + str(signatureData['chunk-size']) + " but " + str(args.chunk_size) + " was given")
                            return None

                        numOfChunks = signatureData['max-length']

                        cumulatedError = 0

                        if signatureData['collection']:

                            maxLength = numOfChunks

                            cumMatch = 0
                            numMatches = 0
                            maxMatch = 0

                            for i in range(len(signature)):

                                cumulatedError = 0

                                for k in range(maxLength):

                                    if len(signature[i]) - 1 < k or len(testSignature) - 1 < k:
                                        cumulatedError += 1
                                    else:
                                        cumulatedError += abs(testSignature[k] - signature[i][k]) / 8

                                match = 1 - (1 / maxLength) * cumulatedError
                                cumMatch += match
                                
                                if match > 0.85:
                                    numMatches += 1 
                                    maxMatch = max(maxMatch, match)
                            
                            cumMatch = (1 / len(signature) * cumMatch)

                            matchList.append([
                                True,
                                signatureData['name'],
                                cumMatch,
                                numMatches,
                                maxMatch
                            ])

                        else:

                            maxLength = max(numOfChunks, len(testSignature))

                            for i in range(maxLength):

                                if len(signature) - 1 < i or len(testSignature) - 1 < i:
                                    cumulatedError += 1
                                else:
                                    cumulatedError += abs(testSignature[i] - signature[i]) / 8

                            match = 1 - (1 / maxLength) * cumulatedError
                            
                            matchList.append([
                                False,
                                signatureData['name'],
                                match
                            ])
                
                displayMatchList(matchList)
    

if __name__ == "__main__":
    exit(main())