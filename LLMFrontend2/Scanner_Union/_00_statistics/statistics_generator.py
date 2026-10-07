"""
Preprocessing Statistics Generator
Generates statistical analysis and visualizations for Scanner-Union preprocessing phase
Shows Logic Unit deduplication efficiency before analysis begins
"""
import logging
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from typing import Dict, List, Any
from collections import defaultdict
import os
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class StatisticsGenerator:
    def __init__(self, output_dir: str = None):
        """
        Initialize statistics generator
        
        Args:
            output_dir: Directory to save statistics images
        """
        # Use AI_ANALYSIS_DIR for statistics output
        ai_analysis_dir = os.environ.get('AI_ANALYSIS_DIR', '/tmp/ai-codeql')
        self.output_dir = output_dir or os.path.join(ai_analysis_dir, 'statistics')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set plotting style
        try:
            plt.style.use('seaborn-v0_8-darkgrid')
        except:
            plt.style.use('seaborn-darkgrid')  # Fallback for older versions
        sns.set_palette("husl")
    
    def generate_statistics(self, logic_unit_manager, connections, decompositions) -> Dict[str, Any]:
        """
        Generate comprehensive statistics from analysis results
        """
        stats = {
            'timestamp': datetime.now().isoformat(),
            'total_paths': len(decompositions),
            'total_units': len(logic_unit_manager.units),
            'unit_details': self._analyze_units(logic_unit_manager),
            'reuse_metrics': self._calculate_reuse_metrics(logic_unit_manager, decompositions),
            'segment_distribution': self._analyze_segment_distribution(decompositions),
            'connection_analysis': self._analyze_connections(connections, logic_unit_manager)
        }
        
        # Generate visualizations
        self._generate_visualizations(stats)
        
        # Print to console
        self._print_statistics(stats)
        
        # Save raw data
        self._save_raw_data(stats)
        
        return stats
    
    def _analyze_units(self, logic_unit_manager) -> Dict[str, Any]:
        """Analyze LogicUnit details"""
        def _empty_bucket():
            return {
                'count': 0,
                'total_steps': 0,
                'total_paths': 0,
                'step_distribution': [],
                'path_distribution': []
            }

        unit_analysis = {
            'by_type': defaultdict(_empty_bucket),
            'virtual_count': 0,
        }

        for unit in logic_unit_manager.units.values():
            if getattr(unit, 'is_virtual', False):
                unit_analysis['virtual_count'] += 1
                continue
            unit_type = unit.segment_type
            unit_analysis['by_type'][unit_type]['count'] += 1
            unit_analysis['by_type'][unit_type]['total_steps'] += len(unit.steps)
            unit_analysis['by_type'][unit_type]['total_paths'] += len(unit.paths_using)
            unit_analysis['by_type'][unit_type]['step_distribution'].append(len(unit.steps))
            unit_analysis['by_type'][unit_type]['path_distribution'].append(len(unit.paths_using))

        return dict(unit_analysis)
    
    def _calculate_reuse_metrics(self, logic_unit_manager, decompositions) -> Dict[str, Any]:
        """Calculate reuse efficiency metrics (excludes virtual units)"""
        total_segments = sum(1 for d in decompositions.values()
                           for seg_type in ['backward', 'intermediate', 'forward']
                           if getattr(d, f'{seg_type}_steps', []))

        real_units = [u for u in logic_unit_manager.units.values()
                      if not getattr(u, 'is_virtual', False)]
        unique_real = len(real_units)
        virtual_count = len(logic_unit_manager.units) - unique_real

        return {
            'total_segments': total_segments,
            'unique_units': unique_real,
            'virtual_units': virtual_count,
            'reuse_ratio': total_segments / max(1, unique_real),
            'average_paths_per_unit': sum(len(u.paths_using) for u in real_units) / max(1, unique_real)
        }
    
    def _analyze_segment_distribution(self, decompositions) -> Dict[str, int]:
        """Analyze how paths are distributed across segment types"""
        distribution = {
            'paths_with_backward': 0,
            'paths_with_intermediate': 0,
            'paths_with_forward': 0,
            'paths_with_all_three': 0,
            'paths_with_virtual_backward': 0,
            'paths_with_virtual_forward': 0,
        }

        for decomp in decompositions.values():
            has_backward = bool(decomp.backward_steps)
            has_intermediate = bool(decomp.intermediate_steps)
            has_forward = bool(decomp.forward_steps)

            if has_backward:
                distribution['paths_with_backward'] += 1
            if has_intermediate:
                distribution['paths_with_intermediate'] += 1
            if has_forward:
                distribution['paths_with_forward'] += 1
            if has_backward and has_intermediate and has_forward:
                distribution['paths_with_all_three'] += 1
            if getattr(decomp, 'backward_is_virtual', False):
                distribution['paths_with_virtual_backward'] += 1
            if getattr(decomp, 'forward_is_virtual', False):
                distribution['paths_with_virtual_forward'] += 1

        return distribution
    
    def _analyze_connections(self, connections, logic_unit_manager) -> Dict[str, Any]:
        """Analyze connection patterns between units"""
        # Get comprehensive connection statistics
        conn_stats = connections.get_connection_statistics()

        # Build set of virtual unit keys for filtering
        virtual_keys = {
            k for k, u in logic_unit_manager.units.items()
            if getattr(u, 'is_virtual', False)
        }

        # Calculate unique units from all connections, excluding virtual
        unique_backward_units = set()
        unique_forward_units = set()
        virtual_backward_units = set()
        virtual_forward_units = set()

        # From path connections
        for path_id, (b, i, f) in connections.path_connections.items():
            if b:
                if b in virtual_keys:
                    virtual_backward_units.add(b)
                else:
                    unique_backward_units.add(b)
            if f:
                if f in virtual_keys:
                    virtual_forward_units.add(f)
                else:
                    unique_forward_units.add(f)

        # Also include units from intermediate contexts
        for contexts in connections.intermediate_contexts.values():
            for bk, fw in contexts:
                if bk and bk != "none":
                    if bk in virtual_keys:
                        virtual_backward_units.add(bk)
                    else:
                        unique_backward_units.add(bk)
                if fw and fw != "none":
                    if fw in virtual_keys:
                        virtual_forward_units.add(fw)
                    else:
                        unique_forward_units.add(fw)

        return {
            **conn_stats,
            'total_intermediate_contexts': len(connections.intermediate_contexts),
            'unique_backward_units': len(unique_backward_units),
            'unique_forward_units': len(unique_forward_units),
            'virtual_backward_units': len(virtual_backward_units),
            'virtual_forward_units': len(virtual_forward_units),
        }
    
    def _generate_visualizations(self, stats):
        """Generate statistical visualizations"""
        # 1. Unit type distribution pie chart
        self._plot_unit_type_distribution(stats['unit_details']['by_type'])
        
        # 2. Step count distribution histogram
        self._plot_step_distribution(stats['unit_details']['by_type'])
        
        # 3. Path reuse distribution
        self._plot_path_reuse_distribution(stats['unit_details']['by_type'])
        
        # 4. Reuse efficiency metrics
        self._plot_reuse_metrics(stats['reuse_metrics'])
        
        # 5. Dual-axis cumulative coverage chart
        self._plot_cumulative_coverage_dual_axis(stats['unit_details']['by_type'])
    
    def _plot_unit_type_distribution(self, by_type_data):
        """Plot unit type distribution"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Pie chart for unit counts
        unit_counts = {k: v['count'] for k, v in by_type_data.items()}
        if unit_counts:
            ax1.pie(unit_counts.values(), labels=unit_counts.keys(), autopct='%1.1f%%')
            ax1.set_title('LogicUnit Distribution by Type')
        
        # Bar chart for average metrics
        types = list(by_type_data.keys())
        if types:
            avg_steps = [v['total_steps']/max(1, v['count']) for v in by_type_data.values()]
            avg_paths = [v['total_paths']/max(1, v['count']) for v in by_type_data.values()]
            
            x = range(len(types))
            width = 0.35
            
            ax2.bar([i - width/2 for i in x], avg_steps, width, label='Avg Steps')
            ax2.bar([i + width/2 for i in x], avg_paths, width, label='Avg Paths')
            ax2.set_xlabel('Segment Type')
            ax2.set_ylabel('Average Count')
            ax2.set_title('Average Steps and Paths per LogicUnit Type')
            ax2.set_xticks(x)
            ax2.set_xticklabels(types)
            ax2.legend()
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'unit_type_distribution.png'), dpi=300)
        plt.close()
    
    def _plot_step_distribution(self, by_type_data):
        """Plot step count distribution"""
        # Determine number of subplots based on available data
        num_types = len(by_type_data)
        if num_types == 0:
            return
        
        fig, axes = plt.subplots(1, min(3, num_types), figsize=(5*min(3, num_types), 5))
        
        # Handle single subplot case
        if num_types == 1:
            axes = [axes]
        
        for idx, (unit_type, data) in enumerate(by_type_data.items()):
            if idx < 3:  # Only plot first 3 types
                ax = axes[idx] if num_types > 1 else axes[0]
                step_dist = data['step_distribution']
                if step_dist:
                    ax.hist(step_dist, bins=20, edgecolor='black')
                    ax.set_title(f'{unit_type.capitalize()} Units - Step Distribution')
                    ax.set_xlabel('Number of Steps')
                    ax.set_ylabel('Count')
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'step_distribution.png'), dpi=300)
        plt.close()
    
    def _plot_path_reuse_distribution(self, by_type_data):
        """Plot path reuse distribution"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Combine all path distributions
        all_path_counts = []
        for data in by_type_data.values():
            all_path_counts.extend(data['path_distribution'])
        
        if all_path_counts:
            # Create histogram with log scale
            ax.hist(all_path_counts, bins=50, edgecolor='black')
            ax.set_xlabel('Number of Paths Using Unit')
            ax.set_ylabel('Number of Units')
            ax.set_title('Path Reuse Distribution (How many paths use each unit)')
            ax.set_yscale('log')
            
            # Add statistics text
            ax.text(0.7, 0.9, f'Max reuse: {max(all_path_counts)} paths',
                   transform=ax.transAxes,
                   bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
            ax.text(0.7, 0.85, f'Avg reuse: {sum(all_path_counts)/len(all_path_counts):.1f} paths',
                   transform=ax.transAxes,
                   bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'path_reuse_distribution.png'), dpi=300)
        plt.close()
    
    def _plot_reuse_metrics(self, reuse_metrics):
        """Plot reuse efficiency metrics"""
        fig, ax = plt.subplots(figsize=(8, 6))
        
        metrics = {
            'Total Segments': reuse_metrics['total_segments'],
            'Unique Units': reuse_metrics['unique_units'],
            'Reuse Ratio': reuse_metrics['reuse_ratio'],
            'Avg Paths/Unit': reuse_metrics['average_paths_per_unit']
        }
        
        # Create bar chart
        bars = ax.bar(range(len(metrics)), list(metrics.values()))
        ax.set_xticks(range(len(metrics)))
        ax.set_xticklabels(list(metrics.keys()), rotation=45, ha='right')
        ax.set_ylabel('Value')
        ax.set_title('Reuse Efficiency Metrics')
        
        # Add value labels on bars
        for i, (bar, v) in enumerate(zip(bars, metrics.values())):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                   f'{v:.1f}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'reuse_metrics.png'), dpi=300)
        plt.close()
    
    def _print_statistics(self, stats):
        """Print statistics to console"""
        from colorama import Fore, Style
        
        print("\n" + "="*80)
        print(Fore.CYAN + "SCANNER-UNION LOGICUNIT USAGE STATISTICS" + Style.RESET_ALL)
        print("="*80)
        print(f"Generated at: {stats['timestamp']}")
        print(f"Output directory: {self.output_dir}")
        print()
        
        # Basic metrics
        virtual_units = stats['reuse_metrics'].get('virtual_units', 0)
        print(Fore.GREEN + "OVERVIEW:" + Style.RESET_ALL)
        print(f"  Total Paths Analyzed: {stats['total_paths']}")
        print(f"  Total Logic Units: {stats['total_units']} (real: {stats['total_units'] - virtual_units}, virtual: {virtual_units})")
        print(f"  Reuse Ratio: {stats['reuse_metrics']['reuse_ratio']:.2f}x (excludes virtual)")
        print(f"  Average Paths per Unit: {stats['reuse_metrics']['average_paths_per_unit']:.1f} (excludes virtual)")
        print()
        
        # Segment distribution
        print(Fore.GREEN + "PATH SEGMENT DISTRIBUTION:" + Style.RESET_ALL)
        seg_dist = stats['segment_distribution']
        print(f"  Paths with backward segment: {seg_dist['paths_with_backward']} (virtual: {seg_dist.get('paths_with_virtual_backward', 0)})")
        print(f"  Paths with intermediate segment: {seg_dist['paths_with_intermediate']}")
        print(f"  Paths with forward segment: {seg_dist['paths_with_forward']} (virtual: {seg_dist.get('paths_with_virtual_forward', 0)})")
        print(f"  Paths with all three segments: {seg_dist['paths_with_all_three']}")
        print()
        
        # By type breakdown
        print(Fore.GREEN + "BREAKDOWN BY SEGMENT TYPE:" + Style.RESET_ALL)
        for seg_type, data in stats['unit_details']['by_type'].items():
            avg_steps = data['total_steps'] / max(1, data['count'])
            avg_paths = data['total_paths'] / max(1, data['count'])
            print(f"\n  {Fore.YELLOW}{seg_type.upper()}{Style.RESET_ALL}:")
            print(f"    Units: {data['count']}")
            print(f"    Total Steps: {data['total_steps']}")
            print(f"    Average Steps per Unit: {avg_steps:.1f}")
            print(f"    Average Paths per Unit: {avg_paths:.1f}")
            if data['path_distribution']:
                max_reuse = max(data['path_distribution'])
                min_reuse = min(data['path_distribution'])
                print(f"    Path Reuse Range: {min_reuse} - {max_reuse} paths")
        
        # Connection analysis
        print(f"\n{Fore.GREEN}CONNECTION ANALYSIS:{Style.RESET_ALL}")
        conn = stats['connection_analysis']
        print(f"  Total paths: {conn.get('total_paths', 0)}")
        print(f"  Complete paths (B-I-F): {conn.get('complete_paths', 0)}")
        print(f"  Partial paths: {conn.get('partial_paths', 0)}")
        if 'path_patterns' in conn:
            print(f"\n  Path patterns:")
            for pattern, count in conn['path_patterns'].items():
                if count > 0:
                    print(f"    {pattern}: {count}")
        print(f"\n  Total connections: {conn.get('total_connections', 0)}")
        print(f"  Total intermediate contexts: {conn.get('total_intermediate_contexts', 0)}")
        print(f"  Unique backward units connected: {conn['unique_backward_units']} (virtual: {conn.get('virtual_backward_units', 0)})")
        print(f"  Unique forward units connected: {conn['unique_forward_units']} (virtual: {conn.get('virtual_forward_units', 0)})")
        if conn.get('intermediate_context_distribution'):
            print(f"\n  Intermediate context distribution:")
            for contexts, count in sorted(conn['intermediate_context_distribution'].items()):
                print(f"    Units with {contexts} context(s): {count}")
        
        print("\n" + "="*80)
        print(f"{Fore.CYAN}Visualizations saved to: {self.output_dir}{Style.RESET_ALL}")
        print("="*80 + "\n")
    
    def _save_raw_data(self, stats):
        """Save raw statistics data as JSON"""
        output_file = os.path.join(self.output_dir, 'statistics_raw.json')
        
        # Convert defaultdict to dict for JSON serialization
        stats_serializable = {
            'timestamp': stats['timestamp'],
            'total_paths': stats['total_paths'],
            'total_units': stats['total_units'],
            'reuse_metrics': stats['reuse_metrics'],
            'segment_distribution': stats['segment_distribution'],
            'connection_analysis': stats['connection_analysis'],
            'unit_details': {
                'by_type': {k: dict(v) for k, v in stats['unit_details']['by_type'].items()}
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(stats_serializable, f, indent=2)
        
        logger.info(f"Raw statistics saved to: {output_file}")
    
    def _plot_cumulative_coverage_dual_axis(self, by_type_data):
        """Plot dual-axis cumulative coverage chart showing Unit-Path relationship"""
        fig, ax1 = plt.subplots(figsize=(14, 8))
        
        # Colors for different segment types
        colors = {
            'backward': '#3498db',    # Blue
            'intermediate': '#2ecc71', # Green  
            'forward': '#e74c3c'      # Red
        }
        
        # Secondary axis for unit counts
        ax2 = ax1.twinx()
        
        # Process data for each segment type
        for seg_type, data in by_type_data.items():
            if not data['path_distribution']:
                continue
                
            # Get unit-path pairs and sort by path count (descending)
            unit_path_counts = sorted(data['path_distribution'], reverse=True)
            total_paths = sum(unit_path_counts)
            
            if total_paths == 0:
                continue
            
            # Calculate cumulative percentages
            cumulative_paths = 0
            x_percentiles = []
            y_cumulative_coverage = []
            unit_counts_at_percentiles = []
            
            # Calculate for each percentile (0%, 10%, 20%, ..., 100%)
            percentile_points = list(range(0, 101, 10))
            
            for percentile in percentile_points:
                # Calculate how many units constitute this percentile
                unit_index = int((percentile / 100.0) * len(unit_path_counts))
                if unit_index == 0 and percentile == 0:
                    x_percentiles.append(0)
                    y_cumulative_coverage.append(0)
                    unit_counts_at_percentiles.append(0)
                else:
                    # Ensure we don't go out of bounds
                    unit_index = min(unit_index, len(unit_path_counts))
                    
                    # Calculate cumulative path coverage up to this percentile
                    cumulative_paths = sum(unit_path_counts[:unit_index])
                    coverage_percentage = (cumulative_paths / total_paths) * 100
                    
                    x_percentiles.append(percentile)
                    y_cumulative_coverage.append(coverage_percentage)
                    unit_counts_at_percentiles.append(unit_index)
            
            # Plot cumulative coverage curve (left axis)
            ax1.plot(x_percentiles, y_cumulative_coverage, 
                    color=colors.get(seg_type, 'gray'),
                    linewidth=2.5,
                    marker='o',
                    markersize=6,
                    label=f'{seg_type.capitalize()} coverage',
                    zorder=3)
            
            # Add shaded area under the curve for visual effect
            ax1.fill_between(x_percentiles, 0, y_cumulative_coverage,
                           color=colors.get(seg_type, 'gray'),
                           alpha=0.1)
            
            # Plot unit count bars (right axis) - only at key percentiles
            key_percentiles = [10, 20, 30, 50, 70, 90, 100]
            bar_width = 2.5
            offset = {'backward': -bar_width, 'intermediate': 0, 'forward': bar_width}
            
            for i, percentile in enumerate(x_percentiles):
                if percentile in key_percentiles:
                    idx = x_percentiles.index(percentile)
                    ax2.bar(percentile + offset.get(seg_type, 0), 
                           unit_counts_at_percentiles[idx],
                           width=bar_width,
                           color=colors.get(seg_type, 'gray'),
                           alpha=0.6,
                           edgecolor='black',
                           linewidth=1)
            
            # Add annotations for key insights
            # Find the percentile where 80% coverage is reached
            for i in range(len(y_cumulative_coverage) - 1):
                if y_cumulative_coverage[i] <= 80 <= y_cumulative_coverage[i + 1]:
                    # Interpolate to find exact percentile
                    percentile_80 = x_percentiles[i] + (80 - y_cumulative_coverage[i]) * \
                                   (x_percentiles[i + 1] - x_percentiles[i]) / \
                                   (y_cumulative_coverage[i + 1] - y_cumulative_coverage[i])
                    
                    # Add annotation
                    ax1.annotate(f'{seg_type}: {percentile_80:.0f}% units → 80% paths',
                               xy=(percentile_80, 80),
                               xytext=(percentile_80 + 15, 80 - 10),
                               arrowprops=dict(arrowstyle='->', 
                                             color=colors.get(seg_type, 'gray'),
                                             lw=1.5),
                               fontsize=10,
                               color=colors.get(seg_type, 'gray'))
                    break
        
        # Configure axes
        ax1.set_xlabel('Unit Percentile (Cumulative %)', fontsize=12)
        ax1.set_ylabel('Cumulative Path Coverage (%)', fontsize=12)
        ax2.set_ylabel('Number of Units', fontsize=12)
        
        ax1.set_xlim(0, 100)
        ax1.set_ylim(0, 105)
        
        # Grid for better readability
        ax1.grid(True, alpha=0.3, linestyle='--')
        ax1.axhline(y=80, color='gray', linestyle=':', alpha=0.5, label='80% coverage threshold')
        
        # Legend
        lines1, labels1 = ax1.get_legend_handles_labels()
        ax1.legend(lines1, labels1, loc='center right', fontsize=10)
        
        # Title
        plt.title('Unit-Path Relationship: Cumulative Coverage Analysis\n' +
                 'How Unit percentiles translate to Path coverage',
                 fontsize=14, pad=20)
        
        # Add explanation text
        explanation = ("Interpretation: Steeper curves indicate higher concentration of path reuse.\n" +
                      "Bars show absolute unit counts at each percentile.")
        ax1.text(0.02, 0.98, explanation, 
                transform=ax1.transAxes,
                verticalalignment='top',
                fontsize=9,
                bbox=dict(boxstyle='round,pad=0.5', facecolor='wheat', alpha=0.8))
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'cumulative_coverage_dual_axis.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        # Also generate a simplified version focusing on the Pareto principle
        self._plot_pareto_analysis(by_type_data)
    
    def _plot_pareto_analysis(self, by_type_data):
        """Generate simplified Pareto analysis visualization"""
        fig, ax = plt.subplots(figsize=(12, 7))
        
        # Collect all unit-path data across all types
        all_units_data = []
        
        for seg_type, data in by_type_data.items():
            if not data['path_distribution']:
                continue
            
            # Create tuples of (unit_id, path_count, segment_type)
            for i, path_count in enumerate(data['path_distribution']):
                all_units_data.append({
                    'unit_id': f"{seg_type}_{i}",
                    'path_count': path_count,
                    'segment_type': seg_type
                })
        
        if not all_units_data:
            plt.close()
            return
        
        # Sort by path count (descending)
        all_units_data.sort(key=lambda x: x['path_count'], reverse=True)
        
        # Calculate cumulative percentage
        total_paths = sum(item['path_count'] for item in all_units_data)
        cumulative_paths = 0
        pareto_data = []
        
        for i, item in enumerate(all_units_data):
            cumulative_paths += item['path_count']
            percentage_of_units = ((i + 1) / len(all_units_data)) * 100
            percentage_of_paths = (cumulative_paths / total_paths) * 100
            pareto_data.append({
                'unit_percentage': percentage_of_units,
                'path_percentage': percentage_of_paths,
                'segment_type': item['segment_type']
            })
        
        # Plot the Pareto curve
        ax.plot([d['unit_percentage'] for d in pareto_data],
                [d['path_percentage'] for d in pareto_data],
                'b-', linewidth=3, label='Cumulative Path Coverage')
        
        # Add diagonal reference line (perfect distribution)
        ax.plot([0, 100], [0, 100], 'k--', alpha=0.5, label='Perfect Distribution')
        
        # Find and annotate 80-20 point
        for i, data_point in enumerate(pareto_data):
            if data_point['path_percentage'] >= 80:
                ax.scatter(data_point['unit_percentage'], 80, 
                          color='red', s=100, zorder=5)
                ax.annotate(f"{data_point['unit_percentage']:.1f}% of units\ncover 80% of paths",
                           xy=(data_point['unit_percentage'], 80),
                           xytext=(data_point['unit_percentage'] + 10, 70),
                           arrowprops=dict(arrowstyle='->', color='red'),
                           fontsize=12,
                           bbox=dict(boxstyle='round,pad=0.5', facecolor='yellow', alpha=0.8))
                break
        
        # Shade the area showing concentration
        ax.fill_between([d['unit_percentage'] for d in pareto_data],
                       0,
                       [d['path_percentage'] for d in pareto_data],
                       alpha=0.2, color='blue')
        
        # Formatting
        ax.set_xlabel('Percentage of Logic Units (%)', fontsize=12)
        ax.set_ylabel('Percentage of Path Coverage (%)', fontsize=12)
        ax.set_title('Pareto Analysis: Logic Unit Efficiency\n' +
                    'Shows concentration of path reuse across all units',
                    fontsize=14, pad=20)
        
        ax.grid(True, alpha=0.3)
        ax.set_xlim(0, 100)
        ax.set_ylim(0, 100)
        
        # Add statistics box
        top_10_percent_idx = int(0.1 * len(pareto_data))
        top_10_coverage = pareto_data[top_10_percent_idx]['path_percentage'] if top_10_percent_idx < len(pareto_data) else 0
        
        stats_text = f"Key Statistics:\n"
        stats_text += f"• Total units: {len(all_units_data)}\n"
        stats_text += f"• Top 10% units cover: {top_10_coverage:.1f}% paths\n"
        stats_text += f"• Average paths per unit: {total_paths/len(all_units_data):.1f}"
        
        ax.text(0.98, 0.02, stats_text,
               transform=ax.transAxes,
               verticalalignment='bottom',
               horizontalalignment='right',
               fontsize=10,
               bbox=dict(boxstyle='round,pad=0.5', facecolor='lightgray', alpha=0.8))
        
        ax.legend(loc='upper left')
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'pareto_analysis.png'),
                   dpi=300, bbox_inches='tight')
        plt.close()