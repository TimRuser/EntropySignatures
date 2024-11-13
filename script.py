import argparse
import os
from collections import Counter
import math
import json
from pathlib import Path
from tabulate import tabulate
import pefile
import pandas as pd
import torch
import numpy as np
import sys

from sklearn.preprocessing import OneHotEncoder

from modelClasses.main import SimplifiedModel, categories

parser = argparse.ArgumentParser(description="Tool to create entropy signatures and match a file with them")
parser.add_argument('mode', type=str, help="Operating mode, can be generate, test or show")
parser.add_argument('input', type=str, nargs="*", help="Input file path")
parser.add_argument('--family', action='store_true', help="Calculates the average signature over the files in the directory")
parser.add_argument('--collection', action='store_true', help="Store signatures individually but as one family")
parser.add_argument('--chunk-size', type=int, default=2048, help="Size of the chunks")
parser.add_argument('--label', type=int, help="Label that every file in the generated dataset will have, 0 = benign, 1 = malware")
parser.add_argument('--use-nn', type=str, help="Use a given neural network for the benchmark")

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


    individualList = [item for item in list if not item[0]]

    if len(individualList) > 0:

        print("Found the following individual matches:")

        sorted_list = sorted(individualList, key=lambda x: x[2], reverse=True)

        formated_list = [[name, f"{value * 100:.2f}%"] for discard, name, value in sorted_list]
        print(tabulate(formated_list, headers=["Name", "Match"]))

    else:
        print("No indidivual matches found")

    print("\n")


    collectionList = [item for item in list if item[0]]    

    if len(collectionList) > 0:
        print("Found the following collection matches:")

        sorted_list = sorted(collectionList, key=lambda x: x[2], reverse=True)

        formated_list = [[name, f"{value * 100:.2f}%", numMatches, f"{maxMatch * 100:.2f}%"] for discard, name, value, numMatches, maxMatch in sorted_list]
        print(tabulate(formated_list, headers=["Collection name", "Cumulated match", "Matches >85%", "Highest match"]))

    else:
        print("No collection matches found")

    print("\n")

def showSignatures():
    
    dirlist = os.listdir("./signatures")

    dirlist = [file for file in dirlist if file.split('.')[-1] == 'json']
    
    showList = []    

    for file in dirlist:

        with open("signatures/" + file, 'r') as f:

            signatureData = json.load(f)

            showList.append([
                signatureData['name'],
                signatureData['max-length'],
                signatureData['chunk-size'],
                signatureData['collection'],
                len(signatureData['usedFiles']) if isinstance(signatureData['usedFiles'], list) else 1
            ])

    print(tabulate(showList, headers=["Name", "Max Length", "Chunk size", "Is collection", "Files used"]))
    
def generate(args, path):
    
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

                        print("Generating signature for " + str(counter) + "/" + str(len(dirList)) + " : " + str(numOfChunks) + " chunks", end="\r")

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

            print("Finished generating signature")

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

                        print("Generating signature for " + str(counter) + "/" + str(len(dirList)) + " : " + str(numOfChunks) + " chunks", end="\r")

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

            print("Finished generating signature")

def test(args, path):
    
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
            return []
        
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
                            
                            maxMatch = max(maxMatch, match)

                            if match > 0.85:
                                numMatches += 1 
                        
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
            
            return matchList

def benchmark(args, path):

    if not path.is_dir():
        print("Path must be a directory")
        return None
    
    dirlist = os.listdir(path)

    listFolders = [folder for folder in dirlist if (path / folder).is_dir()]

    outputList = []

    folderCounter = 0

    for folder in listFolders:

        folderCounter += 1

        dirlist = os.listdir(path / folder)

        allExes = [exe for exe in dirlist if exe.split('.')[-1] == 'exe']

        numDetections = 0

        counter = 0

        for exe in allExes:
            counter += 1

            if not args.use_nn:

                for match in test(args, path / folder / exe):

                    if match[0]:
                        if match[4] > 0.85:
                            numDetections += 1
                            break
                    else:
                        if match[2] > 0.85:
                            numDetections += 1
                            break
                sys.stdout.write('\033[2K\033[1G')
                print("Evaluating folder " + folder + " " + str(folderCounter) + "/" + str(len(listFolders)) +   " : "  + str(counter) + "/" + str(len(allExes)), end='\r')

            else:

                match = nn(args, [args.use_nn, path / folder / exe])
                
                if match > 0.5:
                    numDetections += 1
                sys.stdout.write('\033[2K\033[1G')
                print("Evaluating folder " + folder + " " + str(folderCounter) + "/" + str(len(listFolders)) +   " : "  + str(counter) + "/" + str(len(allExes)), end='\r')

        if len(allExes) > 0:
            outputList.append([
                folder,
                f"{numDetections}/{len(allExes)}",
                f"{(numDetections / len(allExes)) * 100:.2f}%"
            ])
        else:
            outputList.append([
                folder,
                "0/0",
                "0.00%"
            ])

    print(tabulate(outputList, ["Folder", "Flagged files", "Percentage"]))

def getFullSectionName(pe, originalName):

    section_name = originalName
    section_name = section_name.rstrip(b'\x00')

    if section_name.startswith(b'/'):
        offset = int(section_name[1:].decode().strip())
        
        symbol_table_offset = pe.FILE_HEADER.PointerToSymbolTable
        num_symbols = pe.FILE_HEADER.NumberOfSymbols
        string_table_offset = symbol_table_offset + (num_symbols * 18)
        
        full_name = pe.__data__[string_table_offset + offset:].split(b'\x00', 1)[0]
        return full_name.decode(errors='ignore')
        
    else:
        return section_name.decode(errors='ignore').strip()

def sections(args, path):

    pe = pefile.PE(path)

    outputList = []

    for section in pe.sections:

        outputList.append([
            getFullSectionName(pe, section.Name),
            section.SizeOfRawData,
            calculateEntropy(section.get_data())
        ])

    print(tabulate(outputList, headers=["Section", "Size", "Entropy"]))

    pe.close()

def oneHotEncodeSection(name: str):

    oneHotVector = [0 for i in range(len(categories) + 2)]    

    for i, category in enumerate(categories):
        if name == category:
            oneHotVector[i] = 1
            return oneHotVector
    if len(name) != 0:
        oneHotVector[-2] = 1
    else:
        oneHotVector[-1] = 1
    return oneHotVector
        

def dataset(args, path):

    if not (args.label == 1 or args.label == 0):
        print("Label has to be set and either 0 or 1")
        return None

    if not path.is_dir():
            print("Path must be a directory")
            return None
        
    outputData = []

    dirlist = os.listdir(path)

    listFolders = [folder for folder in dirlist if (path / folder).is_dir()]

    folderCounter = 0

    for folder in listFolders:

        folderCounter += 1

        dirlist = os.listdir(path / folder)

        allExes = [exe for exe in dirlist if exe.split('.')[-1] == 'exe']

        counter = 0

        for file in allExes:

            counter += 1

            pe = pefile.PE(path / folder / file)

            fileData = []

            for i in range(12):
                if len(pe.sections) > i:
                    section = pe.sections[i]

                    fileData.append(oneHotEncodeSection(getFullSectionName(pe, section.Name)) + [section.SizeOfRawData] + [calculateEntropy(section.get_data())])
                else:
                    fileData.append(oneHotEncodeSection('') + [0,0])

            with open(path / folder / file, 'rb') as f:

                data = f.read()
                f.seek(0)

                entropyList = []

                for i in range(round(len(data) / 2048)):
                    entropyList.append(calculateEntropy(f.read(2048)))

                f.seek(0)

                outputData.append({
                    'label': args.label,
                    'fullEntropy': calculateEntropy(f.read()),
                    'numSections': len(pe.sections),
                    'minEntropy': min(entropyList),
                    'maxEntropy': max(entropyList),
                    'sections': fileData,
                    'entropyList': entropyList
                })

            sys.stdout.write('\033[2K\033[1G')
            print("Evaluating folder " + folder + " " + str(folderCounter) + "/" + str(len(listFolders)) +   " : "  + str(counter) + "/" + str(len(allExes)), end='\r')


    os.makedirs('datasets/', exist_ok=True)

    pd.DataFrame(outputData).to_json('datasets/' + path.name + '.json', orient='records')

    print("Successfully generated dataset and saved it to dataset/" + path.name + ".json")

def nn(args, path):

    if not isinstance(path,list):
        print("Only one input was given, nn requires an input file and the saved model")
        return None

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = torch.load(Path(path[0]).resolve(), map_location=device)
    model.eval()

    pe = pefile.PE(Path(path[1]).resolve())

    fileData = []    

    for i in range(12):

        if len(pe.sections) > i:
            section = pe.sections[i]

            fileData.append(oneHotEncodeSection(getFullSectionName(pe, section.Name)) + [section.SizeOfRawData] + [calculateEntropy(section.get_data())])
        else:
            fileData.append(oneHotEncodeSection('') + [0,0])

    for entry in fileData:
        entry[-6] /= 5e+8
        for e in range(5):
                entry[-e - 1] /= 8

    tensorInput = torch.tensor(fileData, dtype=torch.float32).to(device)

    with torch.no_grad():
        output = model(tensorInput.unsqueeze(0))

    return output.item()


def main():
    
    args = parseArgs()

    if args.mode == 'show':
        showSignatures()
        return None

    if args.input and args.mode != 'nn':
        path = Path(args.input[0]).resolve()
    elif args.mode == 'nn' and len(args.input) > 0:
        path = args.input
    else:
        print("For the mode " + args.mode + " an input file or folder is required")
        return None

    if args.mode == 'generate':
        generate(args, path)
    elif args.mode == 'test':
        displayMatchList(test(args, path))
    elif args.mode == 'benchmark':
        benchmark(args, path)
    elif args.mode == 'sections':
        sections(args, path)
    elif args.mode == 'nn':
        print("Prediction to be malicious:", f"{nn(args,path) * 100:.2f}%")
    elif args.mode == 'dataset':
        dataset(args, path)
    else:
        print("There is no mode named " + args.mode)

    return None 

if __name__ == "__main__":
    exit(main())