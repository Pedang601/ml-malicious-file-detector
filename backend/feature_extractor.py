import os
import hashlib
import pefile
import magic
import json
import numpy as np
from datetime import datetime

class FeatureExtractor:
    """Extract features from files for ML detection"""
    
    def __init__(self):
        self.feature_names = [
            'file_size', 'entropy', 'section_count', 'imports_count',
            'exports_count', 'resources_count', 'has_certificate',
            'is_packed', 'byte_entropy', 'string_entropy'
        ]
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of file data"""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def extract_pe_features(self, file_path):
        """Extract features from PE files (Windows executables)"""
        features = {}
        
        try:
            pe = pefile.PE(file_path)
            
            # Basic features
            features['file_size'] = os.path.getsize(file_path)
            features['section_count'] = len(pe.sections)
            features['imports_count'] = sum([len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT]) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            features['exports_count'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
            features['resources_count'] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
            features['has_certificate'] = int(hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'))
            
            # Check for packers (heuristic)
            suspicious_sections = [s for s in pe.sections if s.Name.startswith(b'.UPX') or s.Name.startswith(b'.packed')]
            features['is_packed'] = len(suspicious_sections) > 0
            
            # Calculate section entropies
            section_entropies = []
            for section in pe.sections:
                section_data = section.get_data()
                if section_data:
                    section_entropies.append(self.calculate_entropy(section_data))
            
            features['entropy'] = np.mean(section_entropies) if section_entropies else 0
            
            pe.close()
            
        except Exception as e:
            print(f"Error extracting PE features: {e}")
            # Default values
            features = self.get_default_features()
        
        return features
    
    def extract_general_features(self, file_path):
        """Extract general features for any file type"""
        features = {}
        
        try:
            file_size = os.path.getsize(file_path)
            features['file_size'] = file_size
            
            # Read file in binary mode
            with open(file_path, 'rb') as f:
                file_data = f.read(10000)  # Read first 10KB for analysis
                
            # Calculate byte frequency
            byte_counts = np.bincount(np.frombuffer(file_data, dtype=np.uint8))
            byte_probs = byte_counts / len(file_data)
            
            features['entropy'] = self.calculate_entropy(file_data)
            features['byte_entropy'] = features['entropy']
            
            # Count printable strings
            strings = self.extract_strings(file_data)
            features['string_entropy'] = self.calculate_entropy(strings.encode() if strings else b'')
            
            # Default values for PE-specific features
            features['section_count'] = 0
            features['imports_count'] = 0
            features['exports_count'] = 0
            features['resources_count'] = 0
            features['has_certificate'] = 0
            features['is_packed'] = 0
            
        except Exception as e:
            print(f"Error extracting general features: {e}")
            features = self.get_default_features()
        
        return features
    
    def extract_strings(self, data):
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:  # Minimum string length
                    strings.append(current_string)
                current_string = ""
        
        if len(current_string) >= 4:
            strings.append(current_string)
        
        return ' '.join(strings)
    
    def get_default_features(self):
        """Return default feature values"""
        return {
            'file_size': 0,
            'entropy': 0,
            'section_count': 0,
            'imports_count': 0,
            'exports_count': 0,
            'resources_count': 0,
            'has_certificate': 0,
            'is_packed': 0,
            'byte_entropy': 0,
            'string_entropy': 0
        }
    
    def extract_features(self, file_path):
        """Extract all features from file"""
        # Check if it's a PE file
        mime = magic.from_file(file_path, mime=True)
        
        if 'x-dosexec' in mime or 'pe' in mime.lower():
            features = self.extract_pe_features(file_path)
        else:
            features = self.extract_general_features(file_path)
        
        # Add file hash for identification
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        features['file_hash'] = file_hash
        
        return features
    
    def features_to_vector(self, features):
        """Convert features dictionary to numpy array"""
        feature_order = self.feature_names
        vector = [features[name] for name in feature_order]
        return np.array(vector).reshape(1, -1)