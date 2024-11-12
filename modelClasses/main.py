import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader

class SimplifiedModel(nn.Module):
    def __init__(self):
        super(SimplifiedModel, self).__init__()
        
        self.fcIn = nn.Linear(16 * 22, 128) 
        self.fcStart = nn.Linear(128, 32)
        self.fcInner = nn.Linear(32,32)
        self.fcEnd = nn.Linear(32, 16)
        self.fc_out = nn.Linear(16, 1)     
        
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

        self.dropout = nn.Dropout(p=0)

    def forward(self, x):
        x = x.view(x.size(0), -1) 

        x = self.relu(self.fcIn(x))
        x = self.relu(self.fcStart(x))

        numLayers = 1

        for i in range(numLayers):
            x = self.relu(self.fcInner(x))
            if i == round(numLayers / 2):
                pass
                x = self.dropout(x)

        x = self.relu(self.fcEnd(x))
        x = self.sigmoid(self.fc_out(x))        
        
        return x

categories = ['.text', '.rdata', '.pdata', '.reloc', '.rsrc','.bss', '.idata', '.edata', '.sdata', '.tls', '.data', '.debug', '.ndata', '.xdata', 'Overlay']