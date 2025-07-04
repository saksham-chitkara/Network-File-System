# Network File System

A distributed file system that allows clients to access and manipulate files across multiple storage servers, coordinated by a central naming server.

## Overview

This Network File System (NFS) implementation consists of three main components:

1. **Naming Server (NS)**: Central coordinator that manages the file system structure and directs clients to appropriate storage servers
2. **Storage Servers (SS)**: Distributed servers that store and manage the actual files and directories
3. **Clients**: End users that interact with the file system to perform operations like read, write, create, delete, etc.

## Features

- **File Operations**: Read, write, create, delete, copy files
- **Directory Operations**: Create, delete, and list directories
- **Audio Streaming**: Stream audio files directly from storage servers
- **Redundancy**: Automatic file replication across multiple storage servers
- **Fault Tolerance**: System continues functioning when storage servers fail
- **Efficient Search**: LRU caching for improved file lookup performance
- **Concurrent Access**: Multiple clients can read files simultaneously
- **Synchronous and Asynchronous Writing**: Support for both modes depending on operation priority

## Prerequisites

- Linux/Unix based operating system
- GCC compiler
- json-c library: `sudo apt-get install libjson-c-dev`
- Proper network connectivity between machines running the naming server, storage servers, and clients

## Setup and Running the System

Follow these steps to build and run all components of the distributed file system:

### 1. Build All Components

- **Naming Server:**
  ```bash
  gcc -w -pthread naming_server_code/naming_server.c naming_server_code/lru_cache.c -o naming_server_code/a.out -w -ljson-c
  ```
- **Storage Server:**
  ```bash
  gcc -w -pthread storage_server_code/storage_server.c -o storage_server_code/a.out -w -ljson-c
  ```
- **Client:**
  ```bash
  gcc client_code/client.c -o client_code/a.out -w -ljson-c
  ```

### 2. Prepare Storage Server Paths

Before starting the storage server make a "myserver" directory within it and add all files and directories you want for the storage server (can do manually or use create_paths.py). "myserver" directory is must and all files and directories should be in it. Then generate the list of all files and directories in the `myserver` folder using below command:
```bash
cd storage_server_code
python3 populate_paths.py
```
This will create/update `available_paths.txt` so the naming server can access all files in the storage server's `myserver` directory.

To setup multiplible instances of storage server copy "a.out" file from first storage server (setup using storage_server_code directory) and run the code. Prepare paths for each instance the same way

### 3. Start the Naming Server

```bash
cd naming_server_code
./a.out
```
- Runs on default port (usually 43016)
- Listens for connections from storage servers and clients
- Creates a log file (`log.txt`) for monitoring system operations

### 4. Start Storage Servers

- Ensure the `myserver` directory exists:
  ```bash
  mkdir -p storage_server_code/myserver/
  ```
- Set a unique server ID in `storage_server_code/configuration.txt` (e.g., `1`)
- Make sure `available_paths.txt` is up to date (see step 2 above)
- Start the storage server:
  ```bash
  cd storage_server_code
  ./a.out <server_id> <naming_server_ip> <naming_server_port> <client_port>
  ```
  Example:
  ```bash
  ./a.out 1 192.168.1.100 43016 3000
  ```

### 5. Start the Client

```bash
cd client_code
./a.out <naming_server_ip> <naming_server_port>
```
Example:
```bash
./a.out 192.168.1.100 43016
```

Once connected, the client will present an interactive interface for performing file operations.

## Client Operations

Once the client is running, you can perform the following operations through the interactive interface:

### 1. Read a File
```
read
[Enter file path]
```
This operation contacts the naming server to locate the file, then establishes a direct connection to the appropriate storage server to read the file contents.

### 2. Write to a File
```
write
[Enter file path]
[Enter 1 for priority/synchronous write or 0 for normal/asynchronous write]
[Enter 1 to append or 0 to overwrite]
[Enter "String" or "File" to specify input method]
[Enter content or file path depending on previous choice]
```
This operation allows you to write content to a file, either by inputting a string directly or by providing a local file path. Priority writes ensure data is fully written before returning, while normal writes acknowledge the request immediately.

### 3. Delete a File or Directory
```
delete
[Enter path]
```
Sends a request to delete the specified file or directory from the file system.

### 4. Create a File or Directory
```
create
[Enter path]
[Enter name]
[Enter 1 for directory or 0 for file]
```
Creates a new file or directory at the specified location in the file system.

### 5. Copy a File or Directory
```
copy
[Enter source path]
[Enter destination path]
```
Copies a file or directory from the source path to the destination path, potentially across different storage servers. Try adding "/" at end of directory paths if it doesnt work

### 6. Stream an Audio File
```
stream
[Enter audio file path]
```
Streams an audio file directly from the storage server where it is located.

### 7. Get File Information
```
getfileinfo
[Enter path]
```
Retrieves detailed information about a file, including size, permissions, and last modified time.

### 8. List All Files
```
list
```
Lists all accessible files and directories in the file system.

### 9. Exit the Client
```
STOP
```
Terminates the client application.


## **Description of Files**

### Naming Server Component

#### `naming_server_code/naming_server.c`
- Implements the core functionality of the naming server
- Manages the overall file system tree structure
- Handles client requests and directs them to appropriate storage servers
- Provides redundancy through backup mechanisms for high availability
- Uses a tree-based structure to represent the file system hierarchy
- Handles storage server registration and deregistration
- Implements path resolution logic to locate files in the distributed system
- Maintains consistency across multiple storage servers

#### `naming_server_code/headers.h`
- Contains necessary data structures and definitions for the naming server
- Defines the TreeNode structure used for the file system hierarchy
- Includes constants for maximum path lengths, buffer sizes, etc.
- Contains definitions for storage server management
- Provides structures for backup and redundancy handling

#### `naming_server_code/lru_cache.c`
- Implements a Least Recently Used (LRU) caching mechanism
- Improves performance by caching frequently accessed file paths
- Reduces load on storage servers by serving cached content
- Helps optimize path resolution by caching recent lookups

### Storage Server Component

#### `storage_server_code/storage_server.c`
- Implements the storage server functionality
- Manages the actual storage of files and directories
- Handles file operations such as read, write, create, delete, etc.
- Communicates with the naming server for registration
- Handles client connections for file access operations
- Provides file locking mechanisms for concurrent access
- Supports file and directory operations (read, write, copy, etc.)
- Implements backup functionality for reliability

#### `storage_server_code/available_paths.txt`
- Configuration file listing the paths accessible by the storage server
- Each line specifies a path that the storage server can serve

#### `storage_server_code/configuration.txt`
- Contains configuration parameters for the storage server
- Specifies the server ID used for identification with the naming server

#### `storage_server_code/create_paths.py`
- Script to create initial directory and file structure for the storage server
- Allows users to set up custom folder hierarchies and files before server startup

#### `storage_server_code/populate_paths.py`
- Scans the `myserver` directory and generates/updates `available_paths.txt`
- Ensures the naming server has an up-to-date list of all files and directories served by the storage server

### Client Component

#### `client_code/client.c`
- Implements the client interface for interacting with the file system
- Provides command-line operations for file manipulation
- Connects to the naming server to locate files
- Establishes direct connections to storage servers for file operations
- Handles file transfers, reads, writes, and other operations
- Supports various file operations like read, write, create, delete, copy, etc.
- Implements transparent access to the distributed file system

## System Operation Flow

### File Operations

1. **Reading a File**:
   - Client contacts the naming server with the file path
   - Naming server locates the appropriate storage server
   - Client receives storage server information and connects directly
   - Client reads the file from the storage server
   - Read operations implement caching for improved performance

2. **Writing to a File**:
   - Client contacts the naming server with the file path
   - Naming server identifies the storage server and checks permissions
   - Client connects directly to the storage server
   - Storage server handles file locking for concurrent access
   - Changes are written to the file
   - For redundancy, changes may be replicated to backup servers

3. **Creating Files/Directories**:
   - Client sends creation request to the naming server
   - Naming server updates its file system tree
   - Naming server selects appropriate storage server based on load balancing
   - Client connects to the storage server to create the actual file/directory
   - Storage server confirms creation

4. **Copying Files**:
   - Client requests file copy operation
   - Naming server determines source and destination storage servers
   - Client facilitates the copy operation between servers or within a server
   - For directories, copy operation is performed recursively

5. **Deleting Files/Directories**:
   - Client sends deletion request to naming server
   - Naming server updates its file system tree
   - Client connects to storage server to perform the actual deletion
   - For directories, deletion is performed recursively

### Redundancy and Fault Tolerance
- Files can be replicated across multiple storage servers
- The naming server tracks which storage servers have copies of each file
- If a primary storage server fails, requests are redirected to backup servers
- Storage servers can be dynamically added or removed from the system
- The system can recover from storage server crashes

### Concurrency Control
- File locking mechanisms prevent conflicts during concurrent writes
- Read operations can occur concurrently
- Write operations are serialized for the same file
- The naming server manages lock coordination across storage servers

### Performance Optimization
- LRU caching improves access to frequently used files
- Load balancing distributes files across available storage servers
- Clients connect directly to storage servers after path resolution
- Large file transfers are optimized with appropriate buffer sizes

## NOTE
currently all the instances of storage servers have replicas so if you want to test backup please remove those before testing.