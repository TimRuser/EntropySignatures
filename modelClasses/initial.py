import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader

class EnhancedModel(nn.Module):
    def __init__(self):
        super(EnhancedModel, self).__init__()
        
        # Define a series of layers for each sublist processing
        self.fc1 = nn.Linear(3, 64)       # First layer for each sublist
        self.fc2 = nn.Linear(64, 128)     # Second layer for each sublist
        self.fc3 = nn.Linear(128, 64)     # Third layer for each sublist
        
        # Define additional layers after concatenation
        self.fc_concat1 = nn.Linear(16 * 64, 256)  # First layer after concatenation
        self.fc_concat2 = nn.Linear(256, 128)      # Second layer after concatenation
        self.fc_concat3 = nn.Linear(128, 64)       # Third layer after concatenation
        self.fc_out = nn.Linear(64, 1)             # Output layer for binary classification
        
        # Activation and output functions
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        # `x` is of shape (batch_size, 16, 3), where we treat each of the 16 sublists as an input
        outputs = []
        
        # Process each of the 16 sublists independently
        for i in range(16):
            sublist_input = x[:, i, :]  # Get each 3-element sublist
            
            # Pass through the first layer for each sublist
            output = self.relu(self.fc1(sublist_input))
            # Pass through the second layer
            output = self.relu(self.fc2(output))
            # Pass through the third layer
            output = self.relu(self.fc3(output))
            
            outputs.append(output)  # Collect the outputs from each sublist
        
        # Concatenate the outputs from all 16 sublists (resulting in a tensor of shape [batch_size, 16 * 64])
        outputs = torch.cat(outputs, dim=1)
        
        # Pass through additional layers after concatenation
        output = self.relu(self.fc_concat1(outputs))
        output = self.relu(self.fc_concat2(output))
        output = self.relu(self.fc_concat3(output))
        
        # Final output layer (binary classification)
        output = self.fc_out(output)  # (batch_size, 1)
        output = self.sigmoid(output)  # Apply sigmoid to get probabilities between 0 and 1
        
        return output
