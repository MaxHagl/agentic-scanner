#!/usr/bin/env python3
"""
Comprehensive training loss plotting utility
Supports: JSONL, JSON, CSV formats
"""

import json
import csv
import argparse
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np


class LossPlotter:
    def __init__(self):
        self.steps = []
        self.losses = []
    
    def load_jsonl(self, filepath):
        """Load from JSONL file (one JSON object per line)"""
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    if 'loss' in entry and 'step' in entry:
                        self.steps.append(entry['step'])
                        self.losses.append(entry['loss'])
    
    def load_json(self, filepath):
        """Load from JSON file (array of objects)"""
        with open(filepath, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    if 'loss' in entry and 'step' in entry:
                        self.steps.append(entry['step'])
                        self.losses.append(entry['loss'])
    
    def load_csv(self, filepath, step_col='step', loss_col='loss'):
        """Load from CSV file"""
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.steps.append(int(row[step_col]))
                self.losses.append(float(row[loss_col]))
    
    def load_file(self, filepath):
        """Auto-detect file format and load"""
        filepath = Path(filepath)
        if filepath.suffix == '.jsonl':
            self.load_jsonl(filepath)
        elif filepath.suffix == '.json':
            self.load_json(filepath)
        elif filepath.suffix == '.csv':
            self.load_csv(filepath)
        else:
            raise ValueError(f"Unsupported file format: {filepath.suffix}")
    
    def get_stats(self):
        """Calculate loss statistics"""
        if not self.losses:
            return {}
        
        return {
            'min': min(self.losses),
            'max': max(self.losses),
            'mean': np.mean(self.losses),
            'std': np.std(self.losses),
            'improvement': ((max(self.losses) - min(self.losses)) / max(self.losses)) * 100,
        }
    
    def plot_simple(self, output_file='loss_plot.png', title='Training Loss'):
        """Create a simple line plot"""
        fig, ax = plt.subplots(figsize=(14, 6))
        
        ax.plot(self.steps, self.losses, linewidth=2.5, color='#3b82f6', label='Loss')
        ax.fill_between(self.steps, self.losses, alpha=0.2, color='#3b82f6')
        
        ax.set_xlabel('Training Steps', fontsize=12, fontweight='bold')
        ax.set_ylabel('Loss', fontsize=12, fontweight='bold')
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.legend(fontsize=11)
        
        # Add statistics
        stats = self.get_stats()
        stats_text = f"Min: {stats['min']:.4f}\nMax: {stats['max']:.4f}\nMean: {stats['mean']:.4f}\nImprovement: {stats['improvement']:.1f}%"
        ax.text(0.02, 0.98, stats_text, transform=ax.transAxes, fontsize=10,
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {output_file}")
        return fig, ax
    
    def plot_with_phases(self, phase_steps, output_file='loss_phases.png', title='Training Loss - Phases'):
        """Create plot with phase boundaries"""
        fig, ax = plt.subplots(figsize=(14, 6))
        
        ax.plot(self.steps, self.losses, linewidth=2.5, color='#3b82f6', label='Loss')
        ax.fill_between(self.steps, self.losses, alpha=0.2, color='#3b82f6')
        
        # Add phase boundaries
        colors = ['#ef4444', '#f59e0b', '#10b981', '#8b5cf6']
        for i, phase_step in enumerate(phase_steps):
            ax.axvline(x=phase_step, color=colors[i % len(colors)], 
                       linestyle='--', linewidth=2, alpha=0.6)
            ax.text(phase_step, ax.get_ylim()[1] * 0.95, f'Phase {i+1}',
                   fontsize=9, color=colors[i % len(colors)], fontweight='bold')
        
        ax.set_xlabel('Training Steps', fontsize=12, fontweight='bold')
        ax.set_ylabel('Loss', fontsize=12, fontweight='bold')
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.legend(fontsize=11)
        
        # Add statistics
        stats = self.get_stats()
        stats_text = f"Min: {stats['min']:.4f}\nMax: {stats['max']:.4f}\nMean: {stats['mean']:.4f}\nImprovement: {stats['improvement']:.1f}%"
        ax.text(0.02, 0.98, stats_text, transform=ax.transAxes, fontsize=10,
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {output_file}")
        return fig, ax
    
    def plot_with_smoothing(self, window_size=10, output_file='loss_smoothed.png'):
        """Create plot with smoothed curve (moving average)"""
        fig, ax = plt.subplots(figsize=(14, 6))
        
        # Original curve
        ax.plot(self.steps, self.losses, linewidth=1, color='#94a3b8', 
               alpha=0.5, label='Raw Loss')
        
        # Smoothed curve (moving average)
        if len(self.losses) >= window_size:
            smoothed = np.convolve(self.losses, np.ones(window_size)/window_size, mode='valid')
            steps_smoothed = self.steps[window_size-1:]
            ax.plot(steps_smoothed, smoothed, linewidth=2.5, color='#3b82f6', 
                   label=f'Smoothed (window={window_size})')
        
        ax.set_xlabel('Training Steps', fontsize=12, fontweight='bold')
        ax.set_ylabel('Loss', fontsize=12, fontweight='bold')
        ax.set_title('Training Loss - Smoothed', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.legend(fontsize=11)
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {output_file}")
        return fig, ax
    
    def print_stats(self):
        """Print statistics to console"""
        if not self.losses:
            print("No data loaded!")
            return
        
        stats = self.get_stats()
        print("\n" + "="*50)
        print("TRAINING LOSS STATISTICS")
        print("="*50)
        print(f"Data points:      {len(self.losses)}")
        print(f"Step range:       {self.steps[0]:,} - {self.steps[-1]:,}")
        print(f"Min loss:         {stats['min']:.4f} (step {self.steps[self.losses.index(stats['min'])]})")
        print(f"Max loss:         {stats['max']:.4f} (step {self.steps[self.losses.index(stats['max'])]})")
        print(f"Mean loss:        {stats['mean']:.4f}")
        print(f"Std deviation:    {stats['std']:.4f}")
        print(f"Total improvement: {stats['improvement']:.1f}%")
        print("="*50 + "\n")


def main():
    parser = argparse.ArgumentParser(description='Plot training loss curves')
    parser.add_argument('input_file', help='Input file (JSONL, JSON, or CSV)')
    parser.add_argument('-o', '--output', help='Output image filename', default='loss_plot.png')
    parser.add_argument('--phases', nargs='+', type=int, help='Phase boundary steps')
    parser.add_argument('--smooth', action='store_true', help='Plot smoothed curve')
    parser.add_argument('--window', type=int, default=10, help='Smoothing window size')
    parser.add_argument('--title', default='Training Loss', help='Plot title')
    parser.add_argument('--stats', action='store_true', help='Print statistics only')
    
    args = parser.parse_args()
    
    # Load data
    plotter = LossPlotter()
    print(f"📖 Loading: {args.input_file}")
    plotter.load_file(args.input_file)
    print(f"✓ Loaded {len(plotter.losses)} data points")
    
    # Print stats
    plotter.print_stats()
    
    if args.stats:
        return
    
    # Create plots
    if args.smooth:
        plotter.plot_with_smoothing(window_size=args.window, 
                                    output_file=args.output.replace('.png', '_smooth.png'))
    elif args.phases:
        plotter.plot_with_phases(args.phases, output_file=args.output.replace('.png', '_phases.png'),
                                 title=args.title)
    else:
        plotter.plot_simple(output_file=args.output, title=args.title)


if __name__ == '__main__':
    main()