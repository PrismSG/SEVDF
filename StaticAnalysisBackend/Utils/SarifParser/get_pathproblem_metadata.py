import json

class SARIFProcessor:
    def __init__(self, sarif_file):
        self.sarif_file = sarif_file
        self.codeql_results = []
        # Count skipped locations
        self.skipped_main_locations = 0
        self.skipped_flow_locations = 0

    class CodeQLResult:
        def __init__(self, rule_id, message, locations, code_flows):
            self.rule_id = rule_id
            self.message = message
            self.locations = locations
            self.code_flows = code_flows

    class Location:
        def __init__(self, file_path, start_line, start_column, end_column, message_text=None):
            self.file_path = file_path
            self.start_line = start_line
            self.start_column = start_column
            self.end_column = end_column
            self.message_text = message_text

    class CodeFlow:
        def __init__(self, thread_flows):
            self.thread_flows = thread_flows

    class ThreadFlow:
        def __init__(self, locations):
            self.locations = locations

    def parse_sarif(self):
        with open(self.sarif_file, 'r') as f:
            data = json.load(f)

        results = data['runs'][0]['results']
        print(f"Processing {len(results)} results from SARIF file")

        for result_index, result in enumerate(results):
            rule_id = result['ruleId']
            message = result['message']['text']
            
            # Process the primary location
            locations = []
            for loc_index, loc in enumerate(result['locations']):
                try:
                    phys_loc = loc['physicalLocation']
                    artifact_loc = phys_loc['artifactLocation']
                    file_path = artifact_loc['uri']
                    
                    # Check whether the region exists
                    if 'region' in phys_loc:
                        region = phys_loc['region']
                        start_line = region.get('startLine', 0)
                        start_column = region.get('startColumn', 0)
                        end_column = region.get('endColumn', 0)
                        locations.append(self.Location(file_path, start_line, start_column, end_column))
                    else:
                        # Increment the counter without detailed logging
                        self.skipped_main_locations += 1
                        continue
                except KeyError as e:
                    self.skipped_main_locations += 1
            
            # Process code-flow information
            code_flows = []
            if 'codeFlows' in result:
                for code_flow_index, code_flow in enumerate(result['codeFlows']):
                    thread_flows = []
                    for thread_flow_index, thread_flow in enumerate(code_flow['threadFlows']):
                        locations = []
                        for location_index, location in enumerate(thread_flow['locations']):
                            try:
                                # Check for required fields
                                if ('location' not in location or 
                                    'physicalLocation' not in location['location'] or 
                                    'artifactLocation' not in location['location']['physicalLocation']):
                                    self.skipped_flow_locations += 1
                                    continue
                                
                                loc_obj = location['location']
                                phys_loc = loc_obj['physicalLocation']
                                artifact_loc = phys_loc['artifactLocation']
                                file_path = artifact_loc['uri']
                                
                                # Extract semantic label from location message
                                message_text = loc_obj.get('message', {}).get('text')

                                # Check whether the region exists
                                if 'region' in phys_loc:
                                    region = phys_loc['region']
                                    start_line = region.get('startLine', 0)
                                    start_column = region.get('startColumn', 0)
                                    end_column = region.get('endColumn', 0)
                                    locations.append(self.Location(file_path, start_line, start_column, end_column, message_text))
                                else:
                                    # Increment the counter
                                    self.skipped_flow_locations += 1
                                    continue
                            except KeyError:
                                self.skipped_flow_locations += 1
                                continue
                            except Exception:
                                self.skipped_flow_locations += 1
                                continue
                                
                        thread_flows.append(self.ThreadFlow(locations))
                    code_flows.append(self.CodeFlow(thread_flows))

            self.codeql_results.append(self.CodeQLResult(rule_id, message, locations, code_flows))
        
        # Print the summary after processing
        print(f"Skipped {self.skipped_main_locations} main locations and {self.skipped_flow_locations} flow locations due to missing region information")
        print(f"Successfully processed {len(self.codeql_results)} CodeQL results")

    def generate_output(self):
        output = ""
        for result in self.codeql_results:
            output += f"Rule ID: {result.rule_id}\n"
            output += f"Message: {result.message}\n"
            for i, location in enumerate(result.locations):
                output += f"Location {i+1}:\n"
                output += f"File path: {location.file_path}\n"
                output += f"Start line: {location.start_line}\n"
                output += f"Start column: {location.start_column}\n"
                output += f"End column: {location.end_column}\n"
            for i, code_flow in enumerate(result.code_flows):
                output += f"Code flow {i+1}:\n"
                for j, thread_flow in enumerate(code_flow.thread_flows):
                    output += f"Thread flow {j+1}:\n"
                    for k, thread_location in enumerate(thread_flow.locations):
                        output += f"Thread location {k+1}:\n"
                        output += f"File path: {thread_location.file_path}\n"
                        output += f"Start line: {thread_location.start_line}\n"
                        output += f"Start column: {thread_location.start_column}\n"
                        output += f"End column: {thread_location.end_column}\n"
        return output
