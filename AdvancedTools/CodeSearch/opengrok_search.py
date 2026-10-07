import os
import sys
import time
import docker
import requests
import logging
from tqdm import tqdm
from colorama import Fore
import argparse
import multiprocessing

# Ensure current directory is in path for local imports
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

from symbol_lookup import get_symbol_lookup

# Do not configure logging here - let the main application handle it

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OPENGROK_TMP_DIR = os.path.join(CURRENT_DIR, "./testopengrok")
OPENGROK_DATA_PATH = os.path.abspath(f'{OPENGROK_TMP_DIR}/data')
OPENGROK_ETC_PATH = os.path.abspath(f'{OPENGROK_TMP_DIR}/etc')

class CodeServiceManager:
    """
    Manages the OpenGrok service.
    Starts the service and synchronizes the status to environment variables after checking the project index.
    """

    def __init__(self, search_path, project_name, port=8080):
        self.search_path = search_path
        self.data_path = OPENGROK_DATA_PATH
        self.etc_path = OPENGROK_ETC_PATH
        self.project_name = project_name
        self.port = port
        
        # Initialize Docker client with better error handling
        try:
            self.client = docker.from_env()
            # Test Docker connection
            self.client.ping()
            logging.debug("Successfully connected to Docker daemon")
        except docker.errors.DockerException as e:
            logging.error(f"Failed to connect to Docker daemon: {e}")
            logging.error("Please ensure Docker is running and you have proper permissions.")
            logging.error("Try: sudo usermod -aG docker $USER (then log out and back in)")
            sys.exit(1)
            
        self.container = None
        self.container_name = os.environ.get('OPENGROK_CONTAINER_NAME', 'opengrok')
        self.base_url = f'http://localhost:{self.port}'
        self.api_url = f'{self.base_url}/api/v1'
        self.auth_token = os.environ.get('OPENGROK_AUTH_TOKEN', 'TOKEN')
        self.headers = {'Authorization': f'Bearer {self.auth_token}'}

    def start_service(self, index_only=False):
        """
        Start the OpenGrok service and update the environment variable 'OPENGROK_STATUS' to 'ready' once the project is indexed.
        Always updates configuration files before starting the container.
        
        Args:
            index_only (bool): If True, only check/perform indexing without further operations
        """
        try:
            # Always update configuration before starting service
            logging.info(Fore.CYAN + "Updating configuration before starting service..." + Fore.RESET)
            config_success = self.update_config()
            if config_success:
                logging.info(Fore.GREEN + "Configuration updated successfully." + Fore.RESET)
            else:
                logging.warning(Fore.YELLOW + "Configuration update failed. Proceeding with service startup anyway." + Fore.RESET)
            
            self._start_opengrok()
            self._wait_until_ready()
            os.environ['OPENGROK_STATUS'] = 'ready'
            logging.info(Fore.GREEN + "Service is ready and environment variable 'OPENGROK_STATUS' is set to 'ready'." + Fore.RESET)
            
            if index_only:
                logging.info(Fore.GREEN + f"Index completed for project: {self.project_name}" + Fore.RESET)
        except Exception as e:
            os.environ['OPENGROK_STATUS'] = 'error'
            logging.error(Fore.RED + f"An error occurred: {e}" + Fore.RESET)
            sys.exit(1)  # Exit with error code

    def _start_opengrok(self):
        """
        Start the OpenGrok Docker container.
        """
        # Ensure read_only.xml exists before starting
        self._ensure_readonly_config()

        try:
            # Check if the container exists (whether running or stopped)
            containers = self.client.containers.list(all=True, filters={'name': self.container_name})
            if containers:
                self.container = containers[0]
                if self.container.status == 'running':
                    logging.info(Fore.CYAN + f'Container {self.container_name} is already running.' + Fore.RESET)
                else:
                    logging.info(Fore.YELLOW + f'Container {self.container_name} exists but is not running. Starting it...' + Fore.RESET)
                    self.container.start()
                    logging.info(Fore.GREEN + f'Container {self.container_name} started.' + Fore.RESET)
            else:
                # Run the OpenGrok Docker container with specified name
                
                volumes = {
                    os.path.abspath(self.search_path): {'bind': f'/opengrok/src/{self.project_name}', 'mode': 'rw'},
                    # os.path.abspath(self.data_path): {'bind': '/opengrok/data', 'mode': 'rw'}, # could set the shared data path to increase the performance.
                    os.path.abspath(self.etc_path): {'bind': '/opengrok/etc', 'mode': 'rw'},
                }
                ports = {'8080/tcp': self.port}
                
                # Keep the container running with a non-terminating command
                command = ['bash', '-c', 'tail -f /dev/null']


                
                environment = {
                    'OPENGROK_IGNORE_PATTERNS': '-i d:.git -i d:.github  -i f:*.json -i d:*seed* -i f:*.js -i f:*.ts -i f:*.tsx -i f:*.jsx -i f:*.tsx',
                    'INDEXER_OPT': "-r off -i f:.git -i d:.git -i f:.github -i d:.github -i f:*.json -i d:*seed* -i f:*.js -i f:*.ts -i f:*.tsx -i f:*.jsx -i f:*.tsx",  # Filter out .git and .github directories
                    'OPENGROK_INDEX_THREADS': '16',
                    'OPENGROK_VERBOSE': 'true',
                    'NOMIRROR': 'true',
                    # 'OPENGROK_CONFIGURATION': '/opengrok/etc/configuration.xml',
                    'REST_TOKEN': 'TOKEN',
                    # 'READONLY_CONFIG_FILE': '/opengrok/etc/read_only.xml',
                }
                
                self.container = self.client.containers.run(
                    'opengrok/docker:latest',
                    name=self.container_name,
                    detach=True,
                    volumes=volumes,
                    ports=ports,
                    environment=environment,
                    dns=['8.8.8.8'],  # Set DNS
                    cpu_count=16,  # Allocate 8 CPUs to container
                    cpu_shares=1024,  # Give higher CPU priority (default is 1024, higher values = more priority)
                    mem_limit='8g',  # Allocate 8GB of memory to the container
                    memswap_limit='12g'  # Allow up to 12GB total (8GB RAM + 4GB swap)
                )
                logging.info(Fore.GREEN + f'Started container {self.container_name}' + Fore.RESET)
                
                # wait 60 seconds
                time.sleep(60)
                # # Execute command inside the Docker root directory
                # renew the configuration file
                command2 = (
                    'opengrok-indexer -a /opengrok/lib/opengrok.jar -- '
                    '-s /opengrok/src '
                    '-d /opengrok/data '
                    '-H -P '
                    '-W /opengrok/etc/configuration.xml'
                )
                
                exit_code, output = self.container.exec_run(cmd=command2, workdir='/', stdout=True, stderr=True)
                
                if exit_code == 0:
                    logging.info(Fore.GREEN + 'Indexing command executed successfully inside the container.' + Fore.RESET)
                else:
                    logging.error(Fore.RED + f'Indexing command failed with exit code {exit_code}' + Fore.RESET)
                    logging.error(Fore.RED + output.decode() + Fore.RESET)
                
                # merge the password config file with read_only.xml
                command = (
                    'opengrok-projadm -b /opengrok '
                    '-c /venv/bin/opengrok-config-merge '
                    '--jar /opengrok/lib/opengrok.jar '
                    '-U http://localhost:8080 '
                    '-R /opengrok/etc/read_only.xml -r -u'
                )
                exit_code, output = self.container.exec_run(cmd=command, workdir='/', stdout=True, stderr=True)

                if exit_code == 0:
                    logging.info(Fore.GREEN + 'Project admin command executed successfully inside the container.' + Fore.RESET)
                else:
                    logging.error(Fore.RED + f'Project admin command failed with exit code {exit_code}' + Fore.RESET)
                    logging.error(Fore.RED + output.decode() + Fore.RESET)

            # Check if project is already indexed, otherwise wait
            if not self.is_project_indexed():
                logging.info(Fore.YELLOW + f"Project {self.project_name} is not indexed. Waiting for indexing to complete..." + Fore.RESET)
            else:
                logging.info(Fore.GREEN + f"Project {self.project_name} is already indexed." + Fore.RESET)
        except Exception as e:
            raise RuntimeError(Fore.RED + f'An error occurred while starting OpenGrok: {e}' + Fore.RESET)

    def _wait_until_ready(self):
        """
        Wait until the OpenGrok service is ready and check if the project is indexed.
        If not indexed, wait until indexing is complete.
        """
        spinner = ['|', '/', '-', '\\']
        attempt = 0
        
        logging.info(Fore.CYAN + "Waiting for OpenGrok service to be ready..." + Fore.RESET)
        
        while True:
            try:
                # Display the spinner
                sys.stdout.write(f"\rWaiting for OpenGrok service... {spinner[attempt % 4]} (Attempt {attempt+1}) ")
                sys.stdout.flush()
                
                # Check if the OpenGrok service is up
                response = requests.get(f'{self.base_url}/source', headers=self.headers)
                if response.status_code == 200:
                    # Log only when the service becomes available
                    if attempt % 10 == 0 or attempt == 0:
                        logging.info(Fore.GREEN + 'OpenGrok service is up.' + Fore.RESET)
                    
                    # Now check if the project is indexed
                    if self.is_project_indexed():
                        sys.stdout.write("\r" + " " * 60 + "\r")  # Clear the current line
                        sys.stdout.flush()
                        logging.info(Fore.GREEN + 'Project is indexed.' + Fore.RESET)
                        return
                    else:
                        # Log every 10 attempts to reduce repeated output
                        if attempt % 10 == 0:
                            sys.stdout.write("\r" + " " * 60 + "\r")  # Clear the current line
                            sys.stdout.flush()
                            logging.info(Fore.YELLOW + 'Project is not indexed. Waiting for indexing to complete...' + Fore.RESET)
                else:
                    # Log every 30 attempts to reduce repeated output
                    if attempt % 30 == 0:
                        sys.stdout.write("\r" + " " * 60 + "\r")  # Clear the current line
                        sys.stdout.flush()
                        logging.info(Fore.YELLOW + 'Waiting for OpenGrok service to be ready...' + Fore.RESET)
            except requests.ConnectionError:
                # Log every 30 attempts to reduce repeated output
                if attempt % 30 == 0:
                    sys.stdout.write("\r" + " " * 60 + "\r")  # Clear the current line
                    sys.stdout.flush()
                    logging.info(Fore.YELLOW + 'Cannot connect to OpenGrok service. Retrying...' + Fore.RESET)
            
            time.sleep(2)
            attempt += 1

    def is_project_indexed(self):
        """
        Check if the desired project is indexed using the API.
        """
        try:
            response = requests.get(f'{self.api_url}/projects/indexed', headers=self.headers)
            if response.status_code == 200:
                indexed_projects = response.json() 
                # Check if the project is in the list of indexed projects
                if self.project_name in indexed_projects:
                    return True
        except requests.RequestException as e:
            logging.error(Fore.RED + f'Error checking indexed projects: {e}' + Fore.RESET)
        return False

    def force_reindex(self):
        """
        Force a reindex of the project, 
        [TODO] not working, need to fix
        """
        return False
        try:
            if not self.container:
                logging.error(Fore.RED + "Container not initialized. Cannot force reindex." + Fore.RESET)
                return False
                
            logging.info(Fore.CYAN + f"Forcing reindex of project: {self.project_name}" + Fore.RESET)
            command = (
                'opengrok-reindex-project -J=-Djava.util.logging.config.file=/opengrok/etc/logging.properties '
                f'-p {self.project_name} -t /opengrok '
                '/opengrok/etc/configuration.xml'
            )
            exit_code, output = self.container.exec_run(cmd=command, workdir='/', stdout=True, stderr=True)
            if exit_code == 0:
                logging.info(Fore.GREEN + f'Reindex command executed successfully for project {self.project_name}' + Fore.RESET)
                self._wait_until_ready()  # Wait for the reindex to complete
                return True
            else:
                logging.error(Fore.RED + f'Reindex command failed with exit code {exit_code}' + Fore.RESET)
                logging.error(Fore.RED + output.decode() + Fore.RESET)
                return False
        except Exception as e:
            logging.error(Fore.RED + f"Error during force reindex: {e}" + Fore.RESET)
            return False

    def _ensure_readonly_config(self):
        """
        Ensure read_only.xml exists with authentication tokens.
        This file is required for API authentication to work properly.
        """
        readonly_xml = os.path.join(self.etc_path, 'read_only.xml')

        if not os.path.exists(readonly_xml):
            # Create directory if not exists
            os.makedirs(self.etc_path, exist_ok=True)

            # Create read_only.xml with authentication tokens
            xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<java version="21.0.8" class="java.beans.XMLDecoder">
 <object class="org.opengrok.indexer.configuration.Configuration" id="Configuration0">
  <void property="authenticationTokens">
    <void method="add">
      <string>TOKEN</string>
    </void>
  </void>
  <void property="allowInsecureTokens">
    <boolean>true</boolean>
  </void>
 </object>
</java>
'''
            try:
                with open(readonly_xml, 'w') as f:
                    f.write(xml_content)
                logging.info(Fore.GREEN + f'Created read_only.xml at {readonly_xml}' + Fore.RESET)
            except Exception as e:
                logging.error(Fore.RED + f'Failed to create read_only.xml: {e}' + Fore.RESET)
        else:
            logging.info(Fore.CYAN + f'read_only.xml already exists at {readonly_xml}' + Fore.RESET)

    def update_config(self):
        """
        Updates the configuration by starting a temporary container without an entrypoint.
        This container is used solely to generate and update the configuration files in the
        mounted etc directory, then it is stopped and removed.
        This method should be called before _start_opengrok to ensure proper configuration.

        Returns:
            bool: True if configuration update was successful, False otherwise
        """
        # Ensure read_only.xml exists before starting
        self._ensure_readonly_config()
        try:
            # Check if the container exists and remove it if necessary
            containers = self.client.containers.list(all=True, filters={'name': self.container_name})
            if containers:
                self.container = containers[0]
                if self.container.status == 'running':
                    logging.info(Fore.YELLOW + f'Container {self.container_name} is already running. Stopping and removing it...' + Fore.RESET)
                    self.container.stop()
                    self.container.remove(force=True)
                else:
                    logging.info(Fore.YELLOW + f'Container {self.container_name} exists. Removing it...' + Fore.RESET)
                    self.container.remove(force=True)
                logging.info(Fore.GREEN + f'Container {self.container_name} has been removed.' + Fore.RESET)
            
            # Set up volumes and other configuration
            volumes = {
                os.path.abspath(self.search_path): {'bind': f'/opengrok/src/{self.project_name}', 'mode': 'rw'},
                os.path.abspath(self.etc_path): {'bind': '/opengrok/etc', 'mode': 'rw'},
            }
            ports = {'8080/tcp': self.port}
            
            environment = {
                'OPENGROK_IGNORE_PATTERNS': '-i d:.git -i d:.github  -i f:*.json -i d:*seed* -i f:*.js -i f:*.ts -i f:*.tsx -i f:*.jsx -i f:*.tsx',
                'INDEXER_OPT': "-r off -i f:.git -i d:.git -i f:.github -i d:.github -i f:*.json -i d:*seed* -i f:*.js -i f:*.ts -i f:*.tsx -i f:*.jsx -i f:*.tsx",
                'OPENGROK_INDEX_THREADS': '16',
                'OPENGROK_VERBOSE': 'true',
                'NOMIRROR': 'true',
                'REST_TOKEN': 'TOKEN',
            }
            
            # Start container with explicitly set entrypoint=None and command=['bash']
            logging.info(Fore.CYAN + f'Starting container {self.container_name} without entrypoint...' + Fore.RESET)
            self.container = self.client.containers.run(
                'opengrok/docker:latest',
                name=self.container_name,
                detach=True,
                volumes=volumes,
                ports=ports,
                environment=environment,
                entrypoint=None,  # Explicitly disable the entrypoint
                command=['bash', '-c', 'tail -f /dev/null'],  # Keep container running with a simple command
                dns=['8.8.8.8'],
                cpu_count=16,
                cpu_shares=1024,
                mem_limit='8g',
                memswap_limit='12g'
            )
            logging.info(Fore.GREEN + f'Container {self.container_name} started without entrypoint.' + Fore.RESET)
            
            # Wait for the container to be fully initialized
            time.sleep(10)
            
            # Execute command2 inside the container
            logging.info(Fore.CYAN + 'Executing indexing command in the container to update configuration...' + Fore.RESET)
            command2 = (
                'opengrok-indexer -a /opengrok/lib/opengrok.jar -- '
                '-s /opengrok/src '
                '-d /opengrok/data '
                '-H -P '
                '-W /opengrok/etc/configuration.xml'
            )
            
            exit_code, output = self.container.exec_run(cmd=command2, workdir='/', stdout=True, stderr=True)
            
            if exit_code == 0:
                logging.info(Fore.GREEN + 'Configuration update completed successfully.' + Fore.RESET)
            else:
                logging.error(Fore.RED + f'Configuration update failed with exit code {exit_code}' + Fore.RESET)
                logging.error(Fore.RED + output.decode() + Fore.RESET)
            
            # Stop and remove the container after configuration update
            logging.info(Fore.CYAN + f'Stopping and removing container {self.container_name} after configuration update...' + Fore.RESET)
            try:
                self.container.stop()
                self.container.remove(force=True)
                self.container = None
                logging.info(Fore.GREEN + f'Container {self.container_name} has been stopped and removed. Ready for normal startup.' + Fore.RESET)
            except Exception as e:
                logging.error(Fore.RED + f'Error during container cleanup: {e}' + Fore.RESET)
            
            # Return success status
            return exit_code == 0
            
        except Exception as e:
            logging.error(Fore.RED + f'An error occurred while starting container without entrypoint: {e}' + Fore.RESET)
            return False
            
    def add_project(self, new_project_name, new_search_path):
        """
        Add a new project to an existing OpenGrok container
        
        Args:
            new_project_name (str): The name of the new project to add
            new_search_path (str): The path to the source code for the new project
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.container or self.container.status != 'running':
                logging.error(Fore.RED + "Container not running. Cannot add project." + Fore.RESET)
                return False
                
            # Create a temporary project directory in the container
            new_src_dir = f"/tmp/{new_project_name}"
            
            # Create a directory link inside the container
            command = f"mkdir -p /opengrok/src/{new_project_name} && ln -sf {new_search_path} /opengrok/src/{new_project_name}/src"
            exit_code, output = self.container.exec_run(cmd=command, workdir='/', stdout=True, stderr=True, user='root')
            if exit_code != 0:
                logging.error(Fore.RED + f"Failed to create project directory: {output.decode()}" + Fore.RESET)
                return False
                
            # Add the project to OpenGrok
            command = (
                f"opengrok-projadm -b /opengrok "
                f"-c /venv/bin/opengrok-config-merge "
                f"--jar /opengrok/lib/opengrok.jar "
                f"-a {new_project_name} "
                f"-U http://localhost:8080"
            )
            exit_code, output = self.container.exec_run(cmd=command, workdir='/', stdout=True, stderr=True)
            if exit_code != 0:
                logging.error(Fore.RED + f"Failed to add project: {output.decode()}" + Fore.RESET)
                return False
                
            # Index the new project
            command = (
                'opengrok-reindex-project -J=-Djava.util.logging.config.file=/opengrok/etc/logging.properties '
                f'-p {new_project_name} -t /opengrok '
                '/opengrok/etc/configuration.xml'
            )
            exit_code, output = self.container.exec_run(cmd=command, workdir='/', stdout=True, stderr=True)
            if exit_code != 0:
                logging.error(Fore.RED + f"Failed to index new project: {output.decode()}" + Fore.RESET)
                return False
                
            # Wait for the indexing to complete
            logging.info(Fore.CYAN + f"Waiting for project {new_project_name} to be indexed..." + Fore.RESET)
            original_project = self.project_name
            self.project_name = new_project_name
            self._wait_until_ready()
            self.project_name = original_project
            
            logging.info(Fore.GREEN + f"Project {new_project_name} has been successfully added and indexed." + Fore.RESET)
            return True
            
        except Exception as e:
            logging.error(Fore.RED + f"Error adding new project: {e}" + Fore.RESET)
            return False


class CodeQueryManager:
    """
    Handles queries to the OpenGrok service.
    Checks the 'OPENGROK_STATUS' environment variable before querying.
    """

    def __init__(self, port=8080):
        self.project_name = os.environ.get('OPENGROK_PROJECT_NAME')
        self.port = port
        self.base_url = f'http://localhost:{self.port}'
        self.api_url = f'{self.base_url}/api/v1'
        self.auth_token = os.environ.get('OPENGROK_AUTH_TOKEN', 'TOKEN')
        self.headers = {'Authorization': f'Bearer {self.auth_token}'}
        self.search_path = os.environ.get('OPENGROK_SEARCH_PATH')

    def query_definition(self, symbol, start=0, max_results=10):
        """
        Query the definitions of a specified symbol.
        """
        logging.info(Fore.YELLOW + f'Querying definition for {symbol}...')
        status = os.environ.get('OPENGROK_STATUS')
        if status != 'ready':
            logging.warning("Service is not ready. Cannot perform query.")
            return []

        url = f'{self.api_url}/search'  
        params = {
            'projects': self.project_name,
            'def': symbol,
            'start': start,
            'maxresults': max_results
        }
        try:
            response = requests.get(url, params=params, headers=self.headers)
            response.raise_for_status()
            results = response.json()
            # logging.info("\nDefinition Query Results:")
            symbol_lookup = get_symbol_lookup()  # Initialize SymbolLookup

            # Process and display results
            filtered_occurrences = []
            if results:
                if isinstance(results, dict) and 'results' in results:
                    results_dict = results['results']
                    for file_path, occurrences in results_dict.items():
                        for occurrence in occurrences:
                            if isinstance(occurrence, dict):
                                tag = occurrence.get('tag')
                                line_number = occurrence.get('lineNumber')

                                # Clean up the file path
                                cleaned_path = file_path
                                project_prefix = f"/{self.project_name}"
                                if file_path.startswith(project_prefix):
                                    cleaned_path = file_path[len(project_prefix):]
                                full_path = f"{self.search_path}/{cleaned_path}"

                                # Check if tag is 'function' or starts with 'function in'
                                if tag and tag.startswith('function'):
                                    try:
                                        result = symbol_lookup.get_function_by_location(full_path, line_number)
                                        function_body = result.get('functionBody') if result else None
                                        if function_body:
                                            occurrence['functionBody'] = function_body
                                            filtered_occurrences.append(occurrence)
                                        else:
                                            logging.warning(f"Function body not found for {symbol} at {file_path}:{line_number}")
                                    except Exception as e:
                                        logging.warning(f"Error getting function body for {symbol} at {file_path}:{line_number}: {e}")
                                elif tag == 'macro':
                                    # Handle macro definitions - use OpenGrok's line content directly
                                    line_content = occurrence.get('line', '')
                                    occurrence['functionBody'] = f"File Path: {full_path}\n{line_number}: {line_content}"
                                    filtered_occurrences.append(occurrence)
                                else:
                                    logging.warning(f"Unsupported tag type: {tag}")
                    if filtered_occurrences:
                        logging.debug(f"\nFile: {file_path}")
                        for idx, occurrence in enumerate(filtered_occurrences, 1):
                            logging.debug(f"  Occurrence {idx}:")
                            for key, value in occurrence.items():
                                logging.debug(f"    {key}: {value}")
                        logging.info(Fore.GREEN + f'Successfully found definitions for {symbol}.')
                else:
                    logging.warning(Fore.RED + "Unexpected response format or no 'results' key found.")
                    logging.warning(Fore.RED + f'Failed to find definitions for {symbol}.')
            else:
                logging.info("No results found")
            return filtered_occurrences
        except requests.RequestException as e:
            logging.error(f'Error querying definitions for symbol "{symbol}": {e}')
            return []

    def query_symbol(self, symbol, start=0, max_results=10):
        """
        Query for a specified symbol.
        """
        status = os.environ.get('OPENGROK_STATUS')
        if status != 'ready':
            logging.warning("Service is not ready. Cannot perform query.")
            return

        url = f'{self.api_url}/search'
        params = {
            'projects': self.project_name,
            'symbol': symbol,
            'start': start,
            'maxresults': max_results
        }
        try:
            response = requests.get(url, params=params, headers=self.headers)
            response.raise_for_status()
            results = response.json()
            logging.info("\nSymbol Query Results:")
            # Process and display results
            if results:
                if isinstance(results, dict) and 'results' in results:
                    results_dict = results['results']
                    for file_path, occurrences in results_dict.items():
                        logging.info(f"\nFile: {file_path}")
                        for idx, occurrence in enumerate(occurrences, 1):
                            logging.info(f"  Occurrence {idx}:")
                            if isinstance(occurrence, dict):
                                for key, value in occurrence.items():
                                    logging.info(f"    {key}: {value}")
                            else:
                                logging.warning(f"    Unexpected occurrence format: {occurrence}")
                else:
                    logging.warning("Unexpected response format or no 'results' key found.")
            else:
                logging.info("No results found")
        except requests.RequestException as e:
            logging.error(f'Error querying symbol "{symbol}": {e}')


def cleanup_docker_containers():
    """
    Clean up all existing opengrok Docker containers.
    """
    try:
        client = docker.from_env()
        # container_name = os.environ.get('OPENGROK_CONTAINER_NAME', 'opengrok')
        container_name = 'opengrok'
        
        # Find all containers with the specified name
        containers = client.containers.list(all=True, filters={'name': container_name})
        
        if not containers:
            logging.info(Fore.CYAN + f"No {container_name} containers found to clean up." + Fore.RESET)
            return
        
        # Stop and remove each container
        for container in containers:
            logging.info(Fore.YELLOW + f"Cleaning up container: {container.name} (ID: {container.id})" + Fore.RESET)
            if container.status == 'running':
                logging.info(Fore.YELLOW + f"Stopping container {container.name}..." + Fore.RESET)
                container.stop()
            logging.info(Fore.YELLOW + f"Removing container {container.name}..." + Fore.RESET)
            container.remove(force=True)
        
        logging.info(Fore.GREEN + f"All {container_name} containers have been removed." + Fore.RESET)
    except Exception as e:
        logging.error(Fore.RED + f"Error during container cleanup: {e}" + Fore.RESET)


def main():
    parser = argparse.ArgumentParser(description='Code Search Service')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--cleanup', action='store_true', help='Clean up all existing OpenGrok containers')
    parser.add_argument('--index', action='store_true', help='Index the specified project and exit')
    parser.add_argument('--reindex', action='store_true', help='Force reindex of the specified project')
    parser.add_argument('--add-project', action='store_true', help='Add a new project to running OpenGrok instance')
    parser.add_argument('--project-name', help='Project name for add-project operation')
    parser.add_argument('--project-path', help='Source path for add-project operation')
    args = parser.parse_args()

    # Set logging level based on --debug flag
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Clean up containers if requested
    if args.cleanup:
        cleanup_docker_containers()
        return
        
    search_path = os.environ.get('OPENGROK_SEARCH_PATH')

    project_name = os.environ.get('OPENGROK_PROJECT_NAME')
    if not project_name:
        logging.error(Fore.RED + "OPENGROK_PROJECT_NAME environment variable is not set." + Fore.RESET)
        sys.exit(1)
        
    port = int(os.environ.get('OPENGROK_PORT', 8080))

    # Start the service
    service_manager = CodeServiceManager(search_path, project_name, port)
    
    # Handle add-project operation
    if args.add_project:
        if not args.project_name or not args.project_path:
            logging.error(Fore.RED + "Both --project-name and --project-path are required for --add-project" + Fore.RESET)
            return
            
        # First make sure the service is running
        service_manager.start_service()
        
        # Then add the new project
        service_manager.add_project(args.project_name, args.project_path)
        return
    
    # Check for index or reindex flags
    if args.reindex:
        service_manager.start_service()  # Make sure service is running
        service_manager.force_reindex()
        return
    elif args.index:
        # Only start the service and wait for indexing to complete, then exit
        service_manager.start_service(index_only=True)
        return
    
    # Normal service start
    service_manager.start_service()

    # Perform query
    query_manager = CodeQueryManager()
    query_manager.search_path = search_path
    symbol = os.environ.get('OPENGROK_TEST_SYMBOL')
    if symbol:
        query_manager.query_definition(symbol)


if __name__ == "__main__":
    main()
