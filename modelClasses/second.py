import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader

class SimplifiedModel(nn.Module):
    def __init__(self):
        super(SimplifiedModel, self).__init__()
        
        self.fcIn = nn.Linear(18 * 16, 128) 
    
        self.fcInner = nn.Linear(128,128)

        self.fc_out = nn.Linear(128, 1)     
        
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

        self.dropout = nn.Dropout(p=0.3)

    def forward(self, x):
        x = x.view(x.size(0), -1) 

        x = self.relu(self.fcIn(x))

        for i in range(6):
            x = self.relu(self.fcInner(x))
            if i == round(6 / 2):
                x = self.dropout(x)

        x = self.fc_out(x)         
        x = self.sigmoid(x)        
        
        return x

class EnhancedModel(nn.Module):
    def __init__(self):
        super(EnhancedModel, self).__init__()
        
        self.fc1 = nn.Linear(18, 64)  
        self.fc2 = nn.Linear(64, 128)  
        self.fc3 = nn.Linear(128, 64)   
        
        self.fc_concat1 = nn.Linear(16 * 64, 256)
        self.fc_concat2 = nn.Linear(256, 128)
        self.fc_concat3 = nn.Linear(128, 64)      
        self.fc_out = nn.Linear(64, 1)             
        
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        outputs = []
        
        for i in range(16):
            sublist_input = x[:, i, :]
            
            output = self.relu(self.fc1(sublist_input))
            output = self.relu(self.fc2(output))
            output = self.relu(self.fc3(output))
            
            outputs.append(output)
        
        outputs = torch.cat(outputs, dim=1)
        
        output = self.relu(self.fc_concat1(outputs))
        output = self.relu(self.fc_concat2(output))
        output = self.relu(self.fc_concat3(output))
        
        output = self.fc_out(output)
        output = self.sigmoid(output)
        
        return output
    

categories = ['.text', '.rdata', '.pdata', '.reloc', '.rsrc','.bss', '.idata', '.edata', '.sdata', '.tls', '.data', '.debug', '.ndata', '.xdata', 'Overlay']