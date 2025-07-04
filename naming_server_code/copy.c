#include "headers.h"

NamingServer *nm;
LRUCache* cache;

typedef struct {
    char* path;
    int depth;
} PathDepth;

int fd_log;
// Helper function to calculate path depth
int calculate_path_depth(const char* path) {
    if (!path) return 0;
    if (strcmp(path, "/") == 0) return 0;
   
    int depth = 0;
    for (const char* p = path; *p; p++) {
        if (*p == '/') depth++;
    }
    return depth;
}

// Comparison function for qsort
int compare_paths(const void* a, const void* b) {
    const PathDepth* path_a = (const PathDepth*)a;
    const PathDepth* path_b = (const PathDepth*)b;
    // Sort by depth in descending order (deeper paths first)
    return path_b->depth - path_a->depth;
}

// --------------------------------------------------------------

TreeNode* create_tree_node(const char* name, int is_directory) {
    TreeNode* node = (TreeNode*)malloc(sizeof(TreeNode));
    strncpy(node->name, name, MAX_FILENAME_LENGTH - 1);
    node->name[MAX_FILENAME_LENGTH - 1] = '\0';
    node->is_directory = is_directory;
    node->parent = NULL;
    node->max_children = MAX_CHILDREN;
    node->children = (TreeNode**)malloc(sizeof(TreeNode*) * node->max_children);
    node->child_count = 0;
    node->storage_servers = (pair*)malloc(sizeof(int) * MAX_STORAGE_SERVERS);
    node->server_count = 0;
    node->is_written_to = 0;
    node->only_read=0;
     //**************** */
    node->only_read = false;
    return node;
}

// Add a child node to a parent node
void add_child_node(TreeNode* parent, TreeNode* child) {
    if (parent->child_count < parent->max_children) {
        parent->children[parent->child_count++] = child;
        child->parent = parent;
    }
}

// Split path into components
void parse_path_components(const char* path, char** components, int* count) {
    char* path_copy = strdup(path);
    char* token = strtok(path_copy, "/");
    *count = 0;
   
    while (token != NULL && *count < MAX_PATH_LENGTH) {
        components[*count] = strdup(token);
        (*count)++;
        token = strtok(NULL, "/");
    }
   
    free(path_copy);
}

// Find a node in the tree given a path
TreeNode* find_node(TreeNode* root, const char* path) {
    if (strcmp(path, "/") == 0) return NULL;

    char* components[MAX_PATH_LENGTH];
    int component_count;
    parse_path_components(path, components, &component_count);
   
    TreeNode* current = root;
    for (int i = 0; i < component_count; i++) {
        int found = 0;
        for (int j = 0; j < current->child_count; j++) {
            if(current->children[j] == NULL) continue;
            // fprintf(stderr, "%s\n", current->children[j]->name);
            if (strcmp(current->children[j]->name, components[i]) == 0) {
                current = current->children[j];
                // fprintf(stderr, "hello\n");
                found = 1;
                break;
            }
        }

        if (!found) {
            // Clean up components
            for (int k = 0; k < component_count; k++) {
                free(components[k]);
            }
            return NULL;
        }
    }
    // Clean up components
    for (int i = 0; i < component_count; i++) {
        free(components[i]);
    }
    fprintf(stderr, "hello\n");
    return current;
}

// Add a storage server ID to a node
void add_server_to_node(TreeNode* node, const int server_id, int for_backup, int sid_of_backup){
    for (int i = 0; i < node->server_count; i++) {
        if (node->storage_servers[i].sid == server_id) {
            // printf("%s ", get_node_path(node));
            // printf("Already registered\n");
            return;  // Server already registered for this node
        }
    }
    if (node->server_count < MAX_STORAGE_SERVERS) {
        node->storage_servers[node->server_count].sid = server_id;
        node->storage_servers[node->server_count].for_backup = for_backup;
        node->storage_servers[node->server_count].sid_of_backup = sid_of_backup;
       
        node->server_count++;
        fprintf(stderr, "added to node\n");
    }
   
}

void cleanup_empty_subtree(TreeNode* node) {
    if (!node) return;
   
    // First recursively clean up all children
    if (node->is_directory && node->children) {
        for (int i = node->child_count - 1; i >= 0; i--) {
            cleanup_empty_subtree(node->children[i]);
        }
    }
   
    // If this node has no storage servers, remove it from its parent
    if(node->server_count == 0){
        if (node->parent) {
            // Find and remove this node from parent's children array
            for (int i = 0; i < node->parent->child_count; i++) {
                if (node->parent->children[i] == node) {
                    // Shift remaining children left
                    for (int j = i; j < node->parent->child_count - 1; j++) {
                        node->parent->children[j] = node->parent->children[j + 1];
                    }
                    node->parent->child_count--;
                    break;
                }
            }
        }
       
        // Free memory
        if (node->children) {
            free(node->children);
        }
        if (node->storage_servers) {
            free(node->storage_servers);
        }
        free(node);
    }
}

void cleanup_empty_subtree2(TreeNode* node) {
    if (!node) return;
   
    // First recursively clean up all children
    if (node->is_directory && node->children) {
        for (int i = node->child_count - 1; i >= 0; i--) {
            cleanup_empty_subtree2(node->children[i]);
        }
    }
   
    //iss function mein sab udana isliye >= 0
    if(node->server_count >= 0){
        if (node->parent) {
            // Find and remove this node from parent's children array
            for (int i = 0; i < node->parent->child_count; i++) {
                if (node->parent->children[i] == node) {
                    // Shift remaining children left
                    for (int j = i; j < node->parent->child_count - 1; j++) {
                        node->parent->children[j] = node->parent->children[j + 1];
                    }
                    i --;
                    node->parent->child_count--;
                    break;
                }
            }
        }
       
        // Free memory
        if (node->children) {
            free(node->children);
        }
        if (node->storage_servers) {
            free(node->storage_servers);
        }
        free(node);
    }
}

void remove_server_from_node(TreeNode* node, const int server_id) {
    for (int i = 0; i < node->server_count; i++) {
        if (node->storage_servers[i].sid == server_id) {
            node->storage_servers[i].sid = -1;
            for(int j = i + 1; j < node->server_count; j ++) {
                node->storage_servers[j - 1] = node->storage_servers[j];
            }
            node->server_count --;
            return;  
        }
    }
}

// Get full path of a node
char* get_node_path(TreeNode* node) {
    char* path = (char*)malloc(MAX_PATH_LENGTH);
    path[0] = '\0';
   
    TreeNode* current = node;
    char** components = (char**)malloc(sizeof(char*) * MAX_PATH_LENGTH);
    int count = 0;
   
    while (current->parent != NULL) {
        components[count++] = current->name;
        current = current->parent;
    }
   
    strcat(path, "/");
    for (int i = count - 1; i >= 0; i--) {
        strcat(path, components[i]);
        if (i > 0) strcat(path, "/");
    }
   
    free(components);
    return path;
}

// Helper function to clone a single node
TreeNode* clone_tree_node(TreeNode* node) {
    if (!node) return NULL;

    TreeNode* new_node = (TreeNode*)malloc(sizeof(TreeNode));
    strcpy(new_node->name, node->name);
    new_node->is_directory = node->is_directory;
    new_node->parent = NULL;
    new_node->child_count = 0;
    new_node->max_children = node->max_children;
    new_node->children = (TreeNode**)malloc(sizeof(TreeNode*) * new_node->max_children);
    new_node->storage_servers = (pair*)malloc(sizeof(pair) * node->server_count);
    memcpy(new_node->storage_servers, node->storage_servers, sizeof(pair) * node->server_count);
    new_node->server_count = node->server_count;
    new_node->is_written_to = node->is_written_to;
    new_node->only_read = node->only_read;

    return new_node;
}

// Helper function to recursively clone a subtree
TreeNode* clone_subtree(TreeNode* src_node) {
    if (!src_node) return NULL;

    TreeNode* new_node = clone_tree_node(src_node);

    for (int i = 0; i < src_node->child_count; i++) {
        TreeNode* cloned_child = clone_subtree(src_node->children[i]);
        cloned_child->parent = new_node;
        new_node->children[new_node->child_count++] = cloned_child;
    }

    return new_node;
}

// Function to copy a subtree
void copy_subtree(TreeNode* src_node, TreeNode* dest_node, TreeNode* root) {
    if (!dest_node->is_directory) {
        printf("Destination is not a directory: %s\n", dest_node->name);
        return;
    }

    // Clone the subtree
    TreeNode* cloned_subtree = clone_subtree(src_node);
    if (!cloned_subtree) {
        printf("Failed to clone subtree from source path: %s\n", src_node->name);
        return;
    }
    fprintf(stderr, "pr\n");

    for(int i = 0; i < cloned_subtree->child_count; i ++) {
        if(cloned_subtree->children[i] == NULL) continue;
        add_child_node(dest_node, cloned_subtree->children[i]);
    }

    // Add the cloned subtree to the destination node
    // add_child_node(dest_node, cloned_subtree);

    printf("Subtree from %s copied to %s\n", src_node->name, dest_node->name);
}

void add_to_accessible_paths(TreeNode* node, StorageServer* ss, char* parent_path){
    if (!node || !ss || !parent_path) return;

    char full_path[MAX_PATH_LENGTH];
    if(strcmp(parent_path, "/") == 0) {
        snprintf(full_path, sizeof(full_path), "%s", node->name);
    }else{
        snprintf(full_path, sizeof(full_path), "%s/%s", parent_path, node->name);
    }

    ss->accessible_paths[ss->path_count] = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
    strcpy(ss->accessible_paths[ss->path_count++], full_path);

    if (node->is_directory && node->children) {
        for (int i = 0; i < node->child_count; i++) {
            add_to_accessible_paths(node->children[i], ss, full_path);
        }
    }

}

void build_path_list(TreeNode* node, const char* current_path, json_object* paths_array) {
    if (!node || !current_path || !paths_array) return;
   
    char* full_path = (char*)malloc(MAX_PATH_LENGTH);
    if (!full_path) return;
   
    // Construct the full path
    if (strcmp(current_path, "/") == 0) {
        if (strcmp(node->name, "/") == 0) {
            snprintf(full_path, MAX_PATH_LENGTH, "/");
        } else {
            snprintf(full_path, MAX_PATH_LENGTH, "/%s", node->name);
        }
    } else {
        snprintf(full_path, MAX_PATH_LENGTH, "%s/%s", current_path, node->name);
    }
   
    // Add path to array if it's not the root
    if (strcmp(full_path, "/") != 0) {
        // Add trailing slash for directories
        if (node->is_directory) {
            size_t len = strlen(full_path);
            if (len + 2 <= MAX_PATH_LENGTH) {
                strcat(full_path, "/");
            }
        }
        json_object_array_add(paths_array, json_object_new_string(full_path));
    }
   
    // Recursively process children
    // printf("%s %d %d\n", node->name, node->children, node->is_directory);
    if (node->is_directory && node->children) {
        // printf("%s\n", node->name);
        for (int i = 0; i < node->child_count; i++) {
            build_path_list(node->children[i], full_path, paths_array);
        }
    }
   
    free(full_path);
}

void delete_node(TreeNode* node){
    if(!node || !node->parent){
        fprintf(stderr, "Node is null or has no parent, cannot delete.\n");
        return;
    }

    TreeNode* parent = node->parent;
    int index_to_remove = -1;

    for(int i = 0; i < parent->child_count; i++){
        if(strcmp(parent->children[i]->name, node->name) == 0){
            index_to_remove = i;
            break;
        }
    }

    if(index_to_remove == -1){
        fprintf(stderr, "Node not found in parent's children array.\n");
        return;
    }

    for(int i = index_to_remove; i < parent->child_count - 1; i++){
        parent->children[i] = parent->children[i + 1];
    }
    parent->child_count--;
    parent->children[parent->child_count] = NULL;

    free_tree_node(node);
}


void free_tree_node(TreeNode *node) {
    free(node);
}


void add_server_to_subtree(TreeNode* node, int server_id, int for_backup, int sid_of_backup){
    if (!node) return;

    add_server_to_node(node, server_id, for_backup, sid_of_backup);

    if (node->is_directory && node->children) {
        for (int i = 0; i < node->child_count; i++) {
            add_server_to_subtree(node->children[i], server_id, for_backup, sid_of_backup);
        }
    }
}

TreeNode* traverse_and_find_insertion_point(TreeNode* root, const char* path, char** remaining_path) {
    if (!root || !path || !remaining_path) return NULL;

    int is_dir = 0;
    if(path[strlen(path) - 1] == '/') is_dir = 1;

    char* components[MAX_PATH_LENGTH];
    int component_count = 0;
    parse_path_components(path, components, &component_count);

    TreeNode* current = root;
    int i;

    // Traverse as far as the path matches the existing tree structure
    for (i = 0; i < component_count; i++) {
        int found = 0;

        for (int j = 0; j < current->child_count; j++) {
            if (strcmp(current->children[j]->name, components[i]) == 0) {
                current = current->children[j];
                found = 1;
                break;
            }
        }

        if (!found) break; // Path diverges here
    }

    size_t remaining_len = 0;
    *remaining_path = (char*)malloc(MAX_PATH_LENGTH);
    (*remaining_path)[0] = '\0';

    for (int k = i; k < component_count; k++) {
        strcat(*remaining_path, components[k]);
        if (k < component_count - 1) strcat(*remaining_path, "/");
    }

    if(is_dir) strcat(*remaining_path, "/");

    for(int k = 0; k < component_count; k++){
        free(components[k]);
    }

    return current; // Return the node where new children need to be inserted
}

TreeNode* traverse_and_find_backup_point(TreeNode* root, const char* path, char** remaining_path, int sid_to_find) {
    if (!root || !path || !remaining_path) return NULL;

    int is_dir = 0;
    if(path[strlen(path) - 1] == '/') is_dir = 1;

    char* components[MAX_PATH_LENGTH];
    int component_count = 0;
    parse_path_components(path, components, &component_count);

    TreeNode* current = root;
    int i;

    // Traverse as far as the path matches the existing tree structure
    for (i = 0; i < component_count; i++) {
        int found = 0;
        for (int j = 0; j < current->child_count; j++) {
            if (strcmp(current->children[j]->name, components[i]) == 0) {
                for(int bk = 0; bk < current -> server_count; bk ++) {
                    if(current->storage_servers[bk].for_backup == 1 && current->storage_servers[bk].sid == sid_to_find) {
                        found = 1;
                        break;
                    }
                }
                if(found == 1) {
                    current = current->children[j];
                }
                break;
            }
        }

        if (!found) break; // Path diverges here
    }

    size_t remaining_len = 0;
    *remaining_path = (char*)malloc(MAX_PATH_LENGTH);
    (*remaining_path)[0] = '\0';

    for (int k = i; k < component_count; k++) {
        strcat(*remaining_path, components[k]);
        if (k < component_count - 1) strcat(*remaining_path, "/");
    }

    if(is_dir) strcat(*remaining_path, "/");

    for(int k = 0; k < component_count; k++){
        free(components[k]);
    }

    return current; // Return the node where new children need to be inserted
}

void add_remaining_path_to_tree(TreeNode** parent1, const char* remaining_path, TreeNode **first_child) {
    if(!parent1) return;
    TreeNode *parent = *parent1;
    if (!parent || !remaining_path || remaining_path[0] == '\0') return;

    char* components[MAX_PATH_LENGTH];
    int component_count = 0;
    parse_path_components(remaining_path, components, &component_count);

    TreeNode* current = parent;

    // Check if the path ends with a trailing slash
    int last_is_directory = (remaining_path[strlen(remaining_path) - 1] == '/');

    // Create nodes for each component and add them as children
    int count = 0;
    for (int i = 0; i < component_count; i++) {
        int is_directory = (i < component_count - 1) || last_is_directory; // All but last are directories, last depends on the slash
        count ++;
        TreeNode* new_node = create_tree_node(components[i], is_directory);
        add_child_node(current, new_node);

        if(count == 1) {
            *first_child = new_node;
        }
        fprintf(stderr, "curr");
        current = new_node;
    }

    for (int i = 0; i < component_count; i++) {
        free(components[i]);
    }
}

void add_backup_paths_to_server(TreeNode* node, int sid, int backed_up_sid, StorageServer* ss){
    if (!node || !ss ) return;

    for (int i = 0; i < node->server_count; i++) {
        if (node->storage_servers[i].sid == sid && node->storage_servers[i].sid_of_backup == backed_up_sid && node->storage_servers[i].for_backup == 1) {
            ss->accessible_paths[ss->path_count] = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
            strcpy(ss->accessible_paths[ss->path_count++], get_node_path(node));
        }
    }

    // Recursively call the function for child nodes if the current node is a directory
    if (node->is_directory && node->children) {
        for (int i = 0; i < node->child_count; i++) {
            add_backup_paths_to_server(node->children[i], sid, backed_up_sid, ss);
        }
    }
}


// tree directory structure functions end here.


void check_storage_server_status(void *arg) {
    int storage_server_id = *((int *) arg);

    json_object* status_check = json_object_new_object();
    json_object_object_add(status_check, "status_check", json_object_new_string("give_report"));
   
    int res = send_message(nm->storage_servers[storage_server_id]->sock, status_check);
    if(res == -1) {
        nm->storage_servers[storage_server_id]->health_status_retries --;
        if(nm->storage_servers[storage_server_id]->health_status_retries == 0) {
            free(nm->storage_servers[storage_server_id]);
            nm->storage_servers[storage_server_id] = NULL;
        }
    }else {
        nm->storage_servers[storage_server_id]->health_status_retries = 3;
    }
    sleep(30);
}


// Initialize the Naming Server
void initialize_naming_server() {
    nm = (NamingServer *) malloc(sizeof(NamingServer));
    nm->storage_server_count = 0;
    nm->client_count = 0;

    pthread_mutex_init(&nm->lock, NULL);
   
    //********************************* */
    pthread_mutex_init(&nm->replication_lock, NULL);
    nm->root = create_tree_node("/", 1);
    memset(nm->storage_servers, 0, sizeof(nm->storage_servers));
    for(int i = 0; i < MAX_STORAGE_SERVERS; i ++) {
        nm->storage_servers[i] = NULL;
    }

    memset(nm->clients_in_queue, 0, sizeof(nm->clients_in_queue));
    for(int i = 0; i < MAX_CLIENTS; i ++) {
        nm->clients_in_queue[i] = NULL;
    }

    cache = lru_cache_create(128);
}

char* get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[INET_ADDRSTRLEN];
    int found = 0;

    // Get list of interfaces
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    // Iterate through interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        // Only interested in IPv4 addresses
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
           
            // Skip loopback interface
            if (strcmp(ifa->ifa_name, "lo") == 0)
                continue;

            // Convert IP to string
            inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
           
            // Skip local and link-local addresses
            if (strncmp(ip, "127.", 4) != 0 && strncmp(ip, "169.254.", 8) != 0) {
                found = 1;
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    return found ? ip : NULL;
}

// Main thread handler for each connection
void* handle_connection(void* arg) {
    int client_socket = *((int*)arg);
    free(arg);

    json_object* request = receive_request(client_socket);
    if (request == NULL) {
        printf("Unsupported Format! Closing socket!\n");
        close(client_socket);
        return NULL;
    }

    json_object* type_obj;
    if (json_object_object_get_ex(request, "type", &type_obj)) {
        const char* type = json_object_get_string(type_obj);

        fprintf(stderr, "%s\n", type);        
        if (strcmp(type, "storage_server_register") == 0) {
            int sid = -1;
            if((sid = handle_storage_server_registration(client_socket, request)) != -1) {
            
          //******************************************************** */
                if(nm->storage_server_count == 3){
                    fprintf(stderr, "started both\n");
                    sleep(1);
                    handle_path_replication(1);
                    // sleep(2);
                    handle_path_replication(2);

                    fprintf(stderr, "replicated both\n");
                }

                while(nm->storage_servers[sid] != NULL && nm->storage_servers[sid]->active == 1) {
                    json_object* response;
                    if((response = receive_request(nm->storage_servers[sid]->sock)) != NULL) {
                        json_object* type_obj1;
                        json_object_object_get_ex(response, "type", &type_obj1);

                        const char* type1 = json_object_get_string(type_obj1);

                        if(strcmp(type1, "naming_server_related") == 0) {
                            json_object *status_obj, *client_id_obj, *client_request_id_obj, *error_msg, *operation_object, *path_obj; //***************** */
                            json_object_object_get_ex(response, "client_id", &client_id_obj); // 0
                            json_object_object_get_ex(response, "request_id", &client_request_id_obj); // 1

                            int client_id = json_object_get_int(client_id_obj);
                            int client_request_id = json_object_get_int(client_request_id_obj);

                            char *request_status = (char *) malloc(sizeof(char) * 256);
                            if (json_object_object_get_ex(response, "status", &status_obj)) {   
                                const char* status = json_object_get_string(status_obj);
                                strcpy(request_status, status);         
                                printf("Storage Server response: %s\n", status);                    
                            }

                            // json_object* message_to_client = json_object_new_object();
                            json_object *object_to_send_to_client = json_object_new_object();

                            if(strcmp(request_status, "success") == 0) {
                                json_object_object_add(object_to_send_to_client, "request_id", json_object_new_int(client_request_id));
                                json_object_object_add(object_to_send_to_client, "status", json_object_new_string("success"));

                                json_object_object_get_ex(response, "operation", &operation_object);
                                const char* operation = json_object_get_string(operation_object);
                                char* req_operation = (char*) malloc(sizeof(char) * 256);
                                strcpy(req_operation, operation);

                                json_object_object_get_ex(response, "path", &path_obj);
                                const char* pth = json_object_get_string(path_obj);
                                char* req_pth = (char*) malloc(sizeof(char) * MAX_PATH_LENGTH);
                                strcpy(req_pth, pth);
                                
                                if(strcmp(req_operation, "create_empty") == 0){
                                    TreeNode* node = NULL;
                                    char* req_path;
                                    if(strncmp(req_pth, "myserver/", 9) == 0){
                                        req_path = strstr(req_pth, "/") + 1;
                                    }
                                    else{
                                        // req_path = req_pth;
                                        req_path = strstr(req_pth, "/");
                                        if(req_path == NULL)
                                            continue;
                                        req_path = req_path + 1;
                                    }
                                    fprintf(stderr, "%s\n", req_path);
                                    node = find_node(nm->root, req_path);

                                    if(node == NULL){
                                        // char* name = (char*) malloc(sizeof(char) * MAX_FILENAME_LENGTH);

                                        // size_t path_len = strlen(req_path);
                                        // int is_directory = 0;
                                       
                                        // // Check if path ends with '/'
                                        // if(path_len > 0 && req_path[path_len - 1] == '/'){
                                        //     is_directory = 1;
                                        //     req_path[path_len - 1] = '\0';  // Remove trailing slash
                                        //     path_len--;
                                        // }

                                        // // extracting the file/dir name
                                        // int i = path_len - 1;
                                        // while(i >= 0 && req_path[i] != '/'){
                                        //     i--;
                                        // }

                                        // strncpy(name, req_path + i + 1, MAX_FILENAME_LENGTH - 1);
                                        // name[MAX_FILENAME_LENGTH - 1] = '\0';
                                       
                                        // TreeNode* node = create_tree_node(name, is_directory);

                                        size_t path_len = strlen(req_path);

                                        // Check if path ends with '/'
                                        if(path_len > 0 && req_path[path_len - 1] == '/'){
                                            req_path[path_len - 1] = '\0';  // Remove trailing slash
                                        }

                                        StorageServer* ss = nm->storage_servers[sid];
                                        // ss->accessible_paths[ss->path_count] = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
                                        // strcpy(ss->accessible_paths[ss->path_count++], req_path);

                                        char* remaining_path = NULL;
                                        TreeNode* insertion_point = traverse_and_find_insertion_point(nm->root, req_path, &remaining_path);

                                        fprintf(stderr, "rem path....%s", remaining_path);

                                        TreeNode *first_child = (TreeNode *) malloc(sizeof(TreeNode));
                                        if(insertion_point){
                                            add_remaining_path_to_tree(&insertion_point, remaining_path, &first_child);
                                        }else{
                                            printf("Insertion point not found.\n");
                                        }
                                        free(remaining_path); 

                                        TreeNode *ft = first_child;
                                        while(ft -> child_count > 0) {
                                            char *gp = get_node_path(ft);
                                            ss->accessible_paths[ss->path_count] = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
                                            strcpy(ss->accessible_paths[ss->path_count++], gp);  

                                            ft = ft->children[0]; 
                                            fprintf(stderr, "%s\n", gp);
                                        }
                                        TreeNode* find = find_node(nm->root, req_path);
                                        if(find != NULL){
                                            fprintf(stderr, "1\n");
                                        }
                                        
                                        // if(client_id == -1)
                                            add_server_to_subtree(first_child, sid + 1, 0, -1);  
                                            // main server ki create ka response phle ayga                  
                                    }
                                    else{ //for backup part

                                        json_object *ssid_obj;//***************** */
                                        json_object_object_get_ex(response, "ssid", &ssid_obj); // 0

                                        int ssid = json_object_get_int(ssid_obj);
                                        fprintf(stderr, "0....\n");
                                        // add_server_to_subtree(node, sid + 1, 0, -1);
                                        char* remaining_path = NULL;
                                        TreeNode* insertion_point = traverse_and_find_backup_point(nm->root, req_path, &remaining_path, sid + 1);

                                        fprintf(stderr, "rem path....%s", remaining_path);

                                        for(int tr = 0; tr < insertion_point->child_count; tr ++) {
                                            TreeNode *f_child = insertion_point->children[tr];
                                            if(f_child != NULL) {
                                                // mangwani hai gggggggggggggggggggggggaur se. (sid of backed up server)
                                                add_server_to_subtree(f_child, sid + 1, 1, ssid);
                                            }
                                        }
                                        // if(insertion_point){
                                        //     add_remaining_path_to_tree(&insertion_point, remaining_path, &first_child);
                                        // }else{
                                        //     printf("Insertion point not found.\n");
                                        // }
                                        free(remaining_path); 
                                    }
                                }
                                else if(strcmp(req_operation, "delete") == 0){
                                    char* req_path = strstr(req_pth, "/") + 1;
                                    TreeNode* node = NULL;
                                    for(int i = 0; i < nm->storage_servers[sid]->current_load; i ++) {
                                        if(nm->storage_servers[sid]->processing_requests[i].reqid != -1 && nm->storage_servers[sid]->processing_requests[i].reqid == client_request_id) {
                                            node = nm->storage_servers[sid]->processing_requests[i].corr_node;
                                        }
                                    }

                                    char* path = (char*) malloc(sizeof(char) * MAX_PATH_LENGTH);
                                    strcpy(path, get_node_path(node));

                                    size_t path_len = strlen(path);
                                    if(path_len > 0 && path[path_len - 1] == '/'){
                                        path[path_len - 1] = '\0';  // Remove trailing slash
                                    }

                                    fprintf(stderr, "%d\n", node->server_count);
                                    remove_server_from_node(node, sid + 1);
                                    fprintf(stderr, "%d\n", node->server_count);

                                    if(node->server_count >= 0){
                                        // delete_node(node);
                                        cleanup_empty_subtree2(node); // lag to shi rha ye //********************* */ check
                                    }

                                    fprintf(stderr, "hello\n");

                                    //removed accessible paths of which had path of the node as substring
                                    StorageServer* ss = nm->storage_servers[sid];
                                    for (int i = 0; i < ss->path_count; i++) {
                                        // fprintf(stderr, "%s, %s\n", ss->accessible_paths[i], path);
                                        if (strstr(ss->accessible_paths[i], path + 1) != NULL) {  // Check if path is a substring
                                            // Shift all subsequent paths to the left
                                            fprintf(stderr, "yes\n");
                                            for (int j = i; j < ss->path_count - 1; j++) {
                                                strcpy(ss->accessible_paths[j], ss->accessible_paths[j + 1]);
                                            }
                                            ss->path_count--;  
                                            i--;
                                        }
                                    }

                                    fprintf(stderr, "hello\n");

                                    for (int i = 0; i < ss->path_count; i++) {
                                        printf("%s\n", ss->accessible_paths[i]);
                                    }

                                }
                                else if(strcmp(req_operation, "copy") == 0){
                                    TreeNode* node = NULL;
                                    for(int i = 0; i < nm->storage_servers[sid]->current_load; i ++) {
                                        if(nm->storage_servers[sid]->processing_requests[i].reqid != -1 && nm->storage_servers[sid]->processing_requests[i].reqid == client_request_id) {
                                            node = nm->storage_servers[sid]->processing_requests[i].corr_node;
                                        }
                                    }  

                                    if(node != NULL){
                                        // add_server_to_subtree(node, sid, 0);
                                        fprintf(stderr, "%s\n", req_pth);
                                        TreeNode *src_node = find_node(nm->root, req_pth);
                                        if(src_node != NULL) {
                                            copy_subtree(src_node, node, nm->root);
                                            fprintf(stderr, "gets\n");

                                            char* path_1 = (char*) malloc(sizeof(char) * MAX_PATH_LENGTH);
                                            strcpy(path_1, get_node_path(node->parent));

                                            fprintf(stderr, "%s\n", path_1);
                                            add_to_accessible_paths(node, nm->storage_servers[sid], path_1);
                                            fprintf(stderr, "%s\n", path_1);
                                        }

                                        for (int i = 0; i < nm->storage_servers[sid]->path_count; i++) {
                                            printf("%s\n", nm->storage_servers[sid]->accessible_paths[i]);
                                        }
                                    }
                                    else{ //for ss recovery
                                        // fprintf(stderr, "no\n");
                                        json_object* obj; //***************** */
                                        json_object_object_get_ex(response, "ssid", &obj);
                                        int backed_up_sid = json_object_get_int(obj);  //jaha backup hua h

                                        add_backup_paths_to_server(nm->root, backed_up_sid, sid, nm->storage_servers[sid]);
                                    }
                                    //pura subtree add krna subtree ke liye
                                }
                            }
                           
                            else if(strcmp(request_status, "error") == 0)  {
                                json_object_object_get_ex(response, "error", &error_msg);
                                const char* error_msg1 = json_object_get_string(error_msg);
                                // json_object_object_add(message_to_client, "status", json_object_new_string("error"));

                                json_object_object_add(object_to_send_to_client, "request_id", json_object_new_int(client_request_id));
                                json_object_object_add(object_to_send_to_client, "status", json_object_new_string("error"));
                                json_object_object_add(object_to_send_to_client, "message", json_object_new_string(error_msg1));
                            }

                            if(client_id != -1 && client_id != -2){
                                Client *cl = nm->clients_in_queue[client_id];
                            
                                for(int i = 0; i < nm->storage_servers[sid]->current_load; i ++) {
                                    if(nm->storage_servers[sid]->processing_requests[i].reqid != -1 && nm->storage_servers[sid]->processing_requests[i].reqid == client_request_id) {
                                        for(int j = i+1; j < nm->storage_servers[sid]->current_load; j ++) {
                                            nm->storage_servers[sid]->processing_requests[j] = nm->storage_servers[sid]->processing_requests[j - 1];
                                        }
                                        nm->storage_servers[sid]->current_load --;
                                        nm->storage_servers[sid]->processing_requests[nm->storage_servers[sid]->current_load].reqid = -1;
                                        nm->storage_servers[sid]->processing_requests[nm->storage_servers[sid]->current_load].corr_node = NULL;
                                        nm->storage_servers[sid]->processing_requests[nm->storage_servers[sid]->current_load].client_associated = NULL;
                                        nm->storage_servers[sid]->processing_requests[nm->storage_servers[sid]->current_load].server_associated = NULL;
                                        break;
                                    }
                                }  

                                for(int i = 0; i < cl->pending_count; i ++) {
                                    if(cl->pending_requests[i].reqid != -1 && cl->pending_requests[i].reqid == client_request_id) {
                                        for(int j = i + 1; j < cl->pending_count; j ++) {
                                            cl->pending_requests[j - 1] = cl->pending_requests[j];
                                        }
                                        cl->pending_count --;
                                        cl->pending_requests[cl->pending_count].reqid = -1;
                                        cl->pending_requests[cl->pending_count].corr_node = NULL;
                                        cl->pending_requests[cl->pending_count].client_associated = NULL;
                                        cl->pending_requests[cl->pending_count].server_associated = NULL;
                                        break;
                                    }
                                }
                                send_message(cl->sock, object_to_send_to_client);
                            }
                        }else if(strcmp(type1, "client_related") == 0) {
                            json_object *status_obj, *client_id_obj, *client_port_obj, *client_ip_obj, *client_request_id_obj, *error_msg;
                            json_object_object_get_ex(response, "client_id", &client_id_obj);
                            json_object_object_get_ex(response, "client_port", &client_port_obj);
                            json_object_object_get_ex(response, "client_ip", &client_ip_obj);
                            json_object_object_get_ex(response, "client_request_id", &client_request_id_obj);

                            int client_id = json_object_get_int(client_id_obj);
                            int client_port = json_object_get_int(client_port_obj);
                            const char* client_ip = json_object_get_string(client_ip_obj);
                            int client_request_id = json_object_get_int(client_request_id_obj);

                            char *request_status = (char *) malloc(sizeof(char) * 256);
                            if (json_object_object_get_ex(response, "status", &status_obj)) {
                                const char* status = json_object_get_string(status_obj);
                                strcpy(request_status, status);
                                printf("Storage Server response: %s\n", status);                    
                            }

                            json_object* message_to_client = json_object_new_object();
                            json_object *object_to_send_to_client = json_object_new_object();

                            if(strcmp(request_status, "success") == 0) {
                                json_object_object_add(object_to_send_to_client, "request_id", json_object_new_int(client_request_id));
                                json_object_object_add(object_to_send_to_client, "status", json_object_new_string("previous_command"));
                                json_object_object_add(object_to_send_to_client, "message", json_object_new_string("success"));

                            }else if(strcmp(request_status, "error") == 0)  {
                                json_object_object_get_ex(response, "error", &error_msg);
                                const char* error_msg1 = json_object_get_string(error_msg);
                                // json_object_object_add(message_to_client, "status", json_object_new_string("error"));

                                json_object_object_add(object_to_send_to_client, "request_id", json_object_new_int(client_request_id));
                                json_object_object_add(object_to_send_to_client, "status", json_object_new_string("previous_command"));
                                json_object_object_add(object_to_send_to_client, "message", json_object_new_string(error_msg1));
                            }

                           

                            for(int i = 0; i < nm->storage_servers[sid]->current_load; i ++) {
                                if(nm->storage_servers[sid]->processing_requests[i].reqid != -1 && nm->storage_servers[sid]->processing_requests[i].reqid == client_request_id) {
                                    for(int j = i + 1; j < nm->storage_servers[sid]->current_load; j ++) {
                                        nm->storage_servers[sid]->processing_requests[j - 1] = nm->storage_servers[sid]->processing_requests[j];
                                    }
                                    nm->storage_servers[sid]->current_load --;
                                    nm->storage_servers[sid]->processing_requests[nm->storage_servers[sid]->current_load].reqid = -1;
                                    nm->storage_servers[sid]->processing_requests[nm->storage_servers[sid]->current_load].corr_node = NULL;
                                    nm->storage_servers[sid]->processing_requests[nm->storage_servers[sid]->current_load].client_associated = NULL;
                                    nm->storage_servers[sid]->processing_requests[nm->storage_servers[sid]->current_load].server_associated = NULL;
                                    break;
                                }
                            }

                            Client *cl = nm->clients_in_queue[client_id];
                            for(int i = 0; i < cl->pending_count; i ++) {
                                if(cl->pending_requests[i].reqid != -1 && cl->pending_requests[i].reqid == client_request_id) {
                                    cl->pending_requests[i].corr_node->is_written_to = 0;
                                    for(int j = i + 1; j < cl->pending_count; j ++) {
                                        cl->pending_requests[j - 1] = cl->pending_requests[j];
                                    }
                                    cl->pending_count --;
                                    cl->pending_requests[cl->pending_count].reqid = -1;
                                    cl->pending_requests[cl->pending_count].corr_node = NULL;
                                    cl->pending_requests[cl->pending_count].client_associated = NULL;
                                    cl->pending_requests[cl->pending_count].server_associated = NULL;
                                    break;
                                }
                            }

                            send_message(cl->sock, object_to_send_to_client);
                        }
                    }else {
                        fprintf(stderr, "band!\n");
                        //*************************************** */
                        StorageServer* ss = nm->storage_servers[sid];

                        for(int i = 0; i < ss->current_load; i ++){
                            if(ss->processing_requests[i].corr_node != NULL && ss->processing_requests[i].corr_node->is_written_to == 1) {
                                json_object *new_obj = json_object_new_object();
                                json_object_object_add(new_obj, "status", json_object_new_string("failure!"));
                                ss->processing_requests[i].corr_node->is_written_to = 0;

                                char buff_msg[1024];
                                sprintf(buff_msg, "write request with request id %d failed because of abrupt server closure!\n", ss->processing_requests[i].reqid);
                                json_object_object_add(new_obj, "message", json_object_new_string(buff_msg));

                                Client *client_associated = ss->processing_requests[i].client_associated;
                                send_message(client_associated->sock, new_obj);
                            }
                        }

                        //jis jis ka backup kr rkha unke struct mein NULL set krunga ki ab backup nhi raha
                        for(int i = 0; i < ss->backup_load; i++){
                            StorageServer* backed_up = ss->backup_of[i];
                            if(backed_up->id == ss->id) backed_up->backup1 = NULL;
                            else if(backed_up->id == ss->id) backed_up->backup2 = NULL;
                        }
                       
                        for(int i = 0; i < nm->storage_servers[sid]->path_count; i++){
                            TreeNode* node = find_node(nm->root, nm->storage_servers[sid]->accessible_paths[i]);
                            if(node){
                            //*************************** */
                            node->only_read = true;
                                remove_server_from_node(node, sid);
                            }

                        }
                   
                        // Create array of PathDepth structures
                        PathDepth* path_depths = (PathDepth*)malloc(sizeof(PathDepth) * nm->storage_servers[sid]->path_count);
                        if (!path_depths) return NULL;
                       
                        // Fill the array with paths and their depths
                        for (int i = 0; i < nm->storage_servers[sid]->path_count; i++) {
                            path_depths[i].path = nm->storage_servers[sid]->accessible_paths[i];
                            path_depths[i].depth = calculate_path_depth(nm->storage_servers[sid]->accessible_paths[i]);
                        }
                       
                        // Sort paths by depth in descending order
                        qsort(path_depths, nm->storage_servers[sid]->path_count, sizeof(PathDepth), compare_paths);
                       
                        // Second pass: clean up empty subtrees (now in correct order)
                        for (int i = 0; i < nm->storage_servers[sid]->path_count; i++) {
                            TreeNode* node = find_node(nm->root, path_depths[i].path);
                            if (node) {
                                cleanup_empty_subtree(node);
                            }
                        }
                       
                        // Clean up
                        free(path_depths);

                        // close(nm->storage_servers[sid]->sock);
                        //************************************** */
                        nm->storage_servers[sid]->active = 0;
                        break;
                    }
                }
            }
        } else if (strcmp(type, "client_request") == 0) {
            int cid = -1;
            cid = handle_client_connection(client_socket, request);
            fprintf(stderr, "%d\n", cid);
            if(cid == -1) {
                fprintf(stderr, "band!\n");

                // close(nm->clients_in_queue[cid]->sock);
                free(nm->clients_in_queue[cid]);
                nm->clients_in_queue[cid] = NULL;
                return 0;
            }

            handle_client_request(nm->clients_in_queue[cid], nm->clients_in_queue[cid]->sock, request);

            while(nm->clients_in_queue[cid] != NULL) {
                json_object* response;
                if((response = receive_request(nm->clients_in_queue[cid]->sock)) != NULL) {
                    json_object* type_obj1;
                    json_object_object_get_ex(response, "type", &type_obj1);

                    const char* type1 = json_object_get_string(type_obj1);
                    if(strcmp(type1, "client_ack") == 0) {
                        json_object *client_request_id_obj;
                        json_object_object_get_ex(response, "final_ack", &client_request_id_obj);
                        json_object *is_write_object;
                        json_object_object_get_ex(response, "is_write", &is_write_object);

                        int client_request_id = json_object_get_int(client_request_id_obj);
                        int is_write = json_object_get_int(is_write_object);

                        Client *cl = nm->clients_in_queue[cid];
                        for(int i = 0; i < cl->pending_count; i ++) {
                            if(cl->pending_requests[i].reqid != -1 && cl->pending_requests[i].reqid == client_request_id) {
                                if(is_write == 1)
                                    cl->pending_requests[i].corr_node->is_written_to = 0;

                                int sidx = cl->pending_requests[i].server_associated->id - 1;                                
                                for(int i = 0; i < nm->storage_servers[sidx]->current_load; i ++) {
                                    if(nm->storage_servers[sidx]->processing_requests[i].reqid != -1 && nm->storage_servers[sidx]->processing_requests[i].reqid == client_request_id) {
                                        for(int j = i + 1; j < nm->storage_servers[sidx]->current_load; j ++) {
                                            nm->storage_servers[sidx]->processing_requests[j - 1] = nm->storage_servers[sidx]->processing_requests[j];
                                        }
                                        nm->storage_servers[sidx]->current_load --;
                                        nm->storage_servers[sidx]->processing_requests[nm->storage_servers[sidx]->current_load].reqid = -1;
                                        nm->storage_servers[sidx]->processing_requests[nm->storage_servers[sidx]->current_load].corr_node = NULL;
                                        nm->storage_servers[sidx]->processing_requests[nm->storage_servers[sidx]->current_load].client_associated = NULL;
                                        nm->storage_servers[sidx]->processing_requests[nm->storage_servers[sidx]->current_load].server_associated = NULL;
                                        break;
                                    }
                                }

                                for(int j = i + 1; j < cl->pending_count; j ++) {
                                    cl->pending_requests[j - 1] = cl->pending_requests[j];
                                }
                                cl->pending_count --;
                                cl->pending_requests[cl->pending_count].reqid = -1;
                                cl->pending_requests[cl->pending_count].corr_node = NULL;
                                cl->pending_requests[cl->pending_count].client_associated = NULL;
                                cl->pending_requests[cl->pending_count].server_associated = NULL;
                                break;
                            }
                        }
                    }else if (strcmp(type, "client_request") == 0) {
                        handle_client_request(nm->clients_in_queue[cid], nm->clients_in_queue[cid]->sock, response);
                    }
                }else {
                    fprintf(stderr, "band!\n");

                    // close(nm->clients_in_queue[cid]->sock);
                    free(nm->clients_in_queue[cid]);
                    nm->clients_in_queue[cid] = NULL;
                    break;
                }
            }

        }
    }
    // close(client_socket);
    return NULL;
}

void find_replicas(int primary_ss_id, StorageServer** replica1, StorageServer** replica2){
    int min_load1 = INT_MAX;
    int min_load2 = INT_MAX;
   
    fprintf(stderr, "%d st\n", primary_ss_id);
    for(int i = 0; i < nm->storage_server_count; i++) {
        if(nm->storage_servers[i] == NULL || !nm->storage_servers[i]->active || i == primary_ss_id - 1) continue;
       
        if(nm->storage_servers[i]->backup_load < min_load1){
            *replica2 = *replica1;
            min_load2 = min_load1;
            *replica1 = nm->storage_servers[i];
            min_load1 = nm->storage_servers[i]->backup_load;
        }

        else if(nm->storage_servers[i]->backup_load < min_load2){
            *replica2 = nm->storage_servers[i];
            min_load2 = nm->storage_servers[i]->backup_load;
        }
    }
    fprintf(stderr, "%d en\n", primary_ss_id);
}

void* handle_backup2(int sid){
    // int sid = *(int*)arg;
    
    fprintf(stderr, "sid %d\n", sid);
    StorageServer* ss = nm->storage_servers[sid - 1];
    char path[MAX_PATH_LENGTH];
    sprintf(path, "replica_%d/", sid);
    fprintf(stderr, "hello..1\n");

    json_object* request = json_object_new_object();
    json_object* paths_array = json_object_new_array();
    json_object* types_array = json_object_new_array();

    char* paths[MAX_PATHS_PER_SERVER];
    int cnt = 0;
    fprintf(stderr, "hello...2\n");

    for(int i = 0; i < ss->pending_backup_cnt; i++){
        TreeNode* node = find_node(nm->root, ss->pending_backup_paths[i]);
        if(node == NULL) continue;

        if(node->is_written_to){
            fprintf(stderr, "hello...3\n");
            paths[cnt] = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
            if(ss->pending_backup_paths[i]) strcpy(paths[cnt++], ss->pending_backup_paths[i]);
        }
        else{
            fprintf(stderr, "hello...4\n");
            json_object_array_add(paths_array, json_object_new_string(ss->pending_backup_paths[i]));
            if (ss->types_backup_paths[i]) json_object_array_add(types_array, json_object_new_string("directory"));
            else json_object_array_add(types_array, json_object_new_string("file"));
        }
    }

    fprintf(stderr, "hello....3\n");

    for(int i = 0; i < cnt; i++){
        ss->pending_backup_paths[i] = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
        if(paths[i])strcpy(ss->pending_backup_paths[i], paths[i]);
    }
    
    fprintf(stderr, "hello....4\n");
    ss->pending_backup_cnt = cnt;

    json_object_object_add(request, "request_code", json_object_new_string("replica"));
    json_object_object_add(request, "request_id", json_object_new_int(-1));
    json_object_object_add(request, "parent_directory", json_object_new_string(path));
    json_object_object_add(request, "storage_port", json_object_new_int(ss->client_port));
    json_object_object_add(request, "storage_ip", json_object_new_string(ss->ip));
    // json_object_object_add(request, "parent_directory", json_object_new_string(path));
    json_object_object_add(request, "paths", paths_array);
    json_object_object_add(request, "types", types_array);

    send_message(ss->backup1->sock, request);
    send_message(ss->backup2->sock, request);
    // json_object_put(request);

    fprintf(stderr, "hello....5\n");

    sleep(25);
}

void* handle_backup(void *arg){
    int sid = *(int *)arg;
    
    fprintf(stderr, "sid %d\n", sid);

    handle_backup2(sid);
}

// Function to handle replication for a path
int handle_path_replication(int primary_ss_id){
    pthread_mutex_lock(&nm->replication_lock);
   
    fprintf(stderr, "%d st1\n", primary_ss_id);
    int active_servers = nm->storage_server_count;
    StorageServer* ss = nm->storage_servers[primary_ss_id - 1];
    fprintf(stderr, "%d st1\n", primary_ss_id);

    if(active_servers > 2){
        StorageServer* replica1 = ss->backup1;
        StorageServer* replica2 = ss->backup2;
        
        fprintf(stderr, "%d st3\n", primary_ss_id);
        if(replica1 == NULL && replica2 == NULL)  {
            StorageServer* replica1_ = malloc(sizeof(StorageServer)); 
            StorageServer* replica2_ = malloc(sizeof(StorageServer));
            find_replicas(primary_ss_id, &replica1_, &replica2_);

            replica1 = replica1_;
            replica2 = replica2_;
        }

        if(replica1 != NULL && replica2 != NULL){
            ss->backup1 = replica1;
            ss->backup2 = replica2;
            fprintf(stderr, "yes\n");
            fprintf(stderr, "%d %d\n", replica1->id, replica2->id);

            // json_object *request = json_object_new_object();
            // json_object_object_add(request, "request_code", json_object_new_string("replica"));
            // json_object_object_add(request, "request_id", json_object_new_int(-1));
            // json_object_object_add(request, "storage_ip", json_object_new_string(ss->ip));
            // json_object_object_add(request, "storage_port", json_object_new_int(ss->client_port));
            // json_object_object_add(request, "ssid", json_object_new_int(primary_ss_id));
            char path[MAX_PATH_LENGTH];
            sprintf(path, "replica_%d", primary_ss_id);
            bool is_dir = true;

            fprintf(stderr, "%s\n", path);

            json_object *request = json_object_new_object();
            json_object_object_add(request, "request_code", json_object_new_string("create_empty"));
            json_object_object_add(request, "request_id", json_object_new_int(-1));
            json_object_object_add(request, "path", json_object_new_string(path));
            json_object_object_add(request, "type", json_object_new_boolean(is_dir));
            json_object_object_add(request, "client_id", json_object_new_int(-1));
            json_object_object_add(request, "storage_ip", json_object_new_string(nm->storage_servers[primary_ss_id - 1]->ip));
            json_object_object_add(request, "storage_port", json_object_new_int(nm->storage_servers[primary_ss_id - 1]->client_port));


            fprintf(stderr, "%d\n", replica1->sock);
            fprintf(stderr, "%d\n", replica2->sock);

            send_message(replica1->sock, request);
            send_message(replica2->sock, request);
            // json_object_put(request);

            json_object *request1 = json_object_new_object();
            json_object* paths_array = json_object_new_array_ext(MAX_PATHS_PER_SERVER);
            json_object* types_array = json_object_new_array_ext(MAX_PATHS_PER_SERVER);
  
            for(int i = 0; i < ss->path_count; i++){
                json_object_array_add(paths_array, json_object_new_string(ss->accessible_paths[i]));
                if(ss->types[i] == 0)
                    json_object_array_add(types_array, json_object_new_string("file"));
                else  
                    json_object_array_add(types_array, json_object_new_string("directory"));
            }

            json_object_object_add(request1, "request_code", json_object_new_string("replica"));
            json_object_object_add(request1, "request_id", json_object_new_int(-1));
            json_object_object_add(request1, "client_id", json_object_new_int(-1));
            json_object_object_add(request1, "parent_directory", json_object_new_string(path));
            json_object_object_add(request1, "storage_ip", json_object_new_string(nm->storage_servers[primary_ss_id - 1]->ip));
            json_object_object_add(request1, "storage_port", json_object_new_int(nm->storage_servers[primary_ss_id - 1]->client_port));
            json_object_object_add(request1, "paths", paths_array);
            json_object_object_add(request1, "types", types_array);

            fprintf(stderr, "%d -- 0\n", primary_ss_id);

            sleep(3);
            send_message(replica1->sock, request1);
            sleep(2);
            send_message(replica2->sock, request1);
            // json_object_put(request);

            fprintf(stderr, "%d -- 1\n", primary_ss_id);
           
            replica1->backup_of[replica1->backup_load++] = ss;
            replica2->backup_of[replica2->backup_load++] = ss;

            fprintf(stderr, "%d -- 1\n", primary_ss_id);

            StorageServer* ss = nm->storage_servers[primary_ss_id - 1];
            for(int i = 0; i < ss->path_count; i++){
                TreeNode* node = find_node(nm->root, ss->accessible_paths[i]);
                add_server_to_node(node, replica1->id, 1, primary_ss_id);
                add_server_to_node(node, replica2->id, 1, primary_ss_id);
            }

            fprintf(stderr, "%d -- 3\n", primary_ss_id);

            //ek thread chalana h that sends the request
            pthread_t thread;
            int *arg = malloc(sizeof(int));
            *arg = primary_ss_id;
            // fprintf(stderr, "%d...\n", arg);

            // Create the thread and pass the argument
            if(pthread_create(&thread, NULL, handle_backup, arg) != 0){
                perror("Failed to create thread");
                // free(arg); // Free memory in case of failure
                pthread_mutex_unlock(&nm->replication_lock);
                return -1;
            }
        }
    }
   
    pthread_mutex_unlock(&nm->replication_lock);
    return 0;
}


// Handle Storage Server registration
int handle_storage_server_registration(int client_socket, json_object* request) {
    pthread_mutex_lock(&nm->lock);

    if (nm->storage_server_count >= MAX_STORAGE_SERVERS) {
        json_object* response = json_object_new_object();
        json_object_object_add(response, "status", json_object_new_string("error"));
        json_object_object_add(response, "message", json_object_new_string("Maximum storage servers reached"));
        send_message(client_socket, response);
        json_object_put(response);
        pthread_mutex_unlock(&nm->lock);
        return -1;
    }

    // Create new storage server entry

    // Get IP and ports from request
    json_object* ip_obj, *nm_port_obj, *client_port_obj, *paths_obj, *existing_id_obj;
    json_object_object_get_ex(request, "ip", &ip_obj);
    json_object_object_get_ex(request, "nm_port", &nm_port_obj);
    json_object_object_get_ex(request, "client_port", &client_port_obj);
    json_object_object_get_ex(request, "accessible_paths", &paths_obj);

    StorageServer* ss;
    int exist_id;
    if((json_object_object_get_ex(request, "ss_id", &existing_id_obj)) && ((exist_id = json_object_get_int(existing_id_obj)) > 0)) {
        printf("%d\n",exist_id);
        ss = nm->storage_servers[exist_id - 1];
        if(ss != NULL && ss->active == 1) {
            json_object* response_fail = json_object_new_object();
            json_object_object_add(response_fail, "status", json_object_new_string("failure"));
            json_object_object_add(response_fail, "error", json_object_new_string("ssid already occupied!")); // tell gaur.

            send_message(client_socket, response_fail);
            return -1;
            // json_object_put(response_fail);
        }

        if(ss == NULL) {
            printf("%d\n",exist_id);
            nm->storage_servers[exist_id - 1] = (StorageServer *) malloc(sizeof(StorageServer));
            ss = nm->storage_servers[exist_id - 1];
            ss->backup1 = NULL;
            ss->backup2 = NULL;

            nm->storage_server_count ++;
        }

        ss->id = exist_id;
        strcpy(ss->ip, json_object_get_string(ip_obj));
        ss->nm_port = json_object_get_int(nm_port_obj);
        ss->client_port = json_object_get_int(client_port_obj);
        ss->sock = client_socket;
        ss->path_count = 0;
            
        //     //******************************* */
        ss->backup_load = 0;
        ss->pending_backup_cnt = 0;
        ss->backup_of = (struct StorageServer **)malloc(sizeof(struct StorageServer*) * MAX_BACKUP_OF);

        ss->active = 1;
        ss->last_heartbeat = time(NULL);
        ss->health_status_retries = 3;

        
        if(ss->backup1 == NULL && ss->backup2 == NULL){
            printf("There is no backup for this Storage server\n");
        }
        else{

            json_object* response_1 = json_object_new_object();
            json_object_object_add(response_1, "status", json_object_new_string("success"));
            json_object_object_add(response_1, "ss_id", json_object_new_int(ss->id)); // tell gaur.

            send_message(client_socket, response_1);

            StorageServer* backup = (ss->backup1 != NULL) ? (ss->backup1) : (ss->backup2);

            const char* path1 = "";
            char* path2 = (char*) malloc(sizeof(char) * 256);
            sprintf(path2, "replica_%d/", ss->id);
    
            int dnode = ss->id - 1;
            int snode = backup->id - 1;
        
            int req_id_client = -2; //code for backup  .............cliient id and req id dono -2 bhejra
            Request p_request;
            p_request.client_associated = NULL;
            p_request.server_associated = nm->storage_servers[dnode];
            p_request.reqid = req_id_client;
            p_request.corr_node = NULL;

            // cl->pending_count ++;
            // cl->pending_requests[cl->pending_count - 1] = p_request;

            int load = p_request.server_associated->current_load ++;
            p_request.server_associated->processing_requests[load] = p_request;

        
            json_object *request = json_object_new_object();
            json_object_object_add(request, "request_code", json_object_new_string("copy1"));
            json_object_object_add(request, "request_id", json_object_new_int(req_id_client));
            json_object_object_add(request, "client_id", json_object_new_int(req_id_client));
            json_object_object_add(request, "destination_path", json_object_new_string(path2));


            json_object_object_add(request, "storage_ip", json_object_new_string(nm->storage_servers[snode]->ip));
            json_object_object_add(request, "storage_port", json_object_new_int(nm->storage_servers[snode]->client_port));
            json_object_object_add(request, "storage_path", json_object_new_string(path1));
            json_object_object_add(request, "ssid", json_object_new_int(snode + 1));

            // int ss_sock = create_socket_to_send_to(nm->storage_servers[dest_server]->ip, nm->storage_servers[dest_server]->nm_port);
            // send_message(ss_sock, request);
            // json_object_put(request);

            send_message(nm->storage_servers[dnode]->sock, request);
            return ss->id - 1;
        }
    }else {
        bool is_found_in_queue = false;
        for(int i = 0; i < nm->storage_server_count; i ++) {
            if(nm->storage_servers[i] == NULL) continue;
            if(strcmp(nm->storage_servers[i]->ip, json_object_get_string(ip_obj)) == 0 && nm->storage_servers[i]->client_port == json_object_get_int(client_port_obj) && nm->storage_servers[i]->active == 0) {
                ss = nm->storage_servers[i];
                is_found_in_queue = true;
                break;
            }
        }

        if(!is_found_in_queue) {
            ss = (StorageServer*)malloc(sizeof(StorageServer));
       
            const char* ip_addr = json_object_get_string(ip_obj);
            strncpy(ss->ip, ip_addr, strlen(ip_addr));
            ss->ip[strlen(ip_addr)] = '\0';
            ss->nm_port = json_object_get_int(nm_port_obj);
            ss->client_port = json_object_get_int(client_port_obj);
            ss->sock = client_socket;
            ss->path_count = 0;
           
            //******************************* */
            ss->backup1 = NULL;
            ss->backup2 = NULL;
            ss->backup_load = 0;
            ss->pending_backup_cnt = 0;
            ss->backup_of = (struct StorageServer **)malloc(sizeof(struct StorageServer*) * MAX_BACKUP_OF);

            ss->active = 1;
            ss->last_heartbeat = time(NULL);
            ss->health_status_retries = 3;

            bool is_found = false;
            for(int i = 0; i < nm->storage_server_count; i ++) {
                if(nm->storage_servers[i] == NULL) {
                    ss->id = i + 1;
                    nm->storage_servers[i] = ss;
                    is_found = true;
                    break;
                }  
            }
            if(!is_found) {
                ss->id = nm->storage_server_count + 1;
                nm->storage_server_count ++;
                nm->storage_servers[nm->storage_server_count - 1] = ss;
            }
        }else {
            pthread_mutex_unlock(&nm->lock);
            return -1;
        }
    }

    fprintf(stderr, "Connection from: %s:%d. Its client port is %d.\n", ss->ip, ss->nm_port, ss->client_port);
    // Handle paths
    json_object_object_get_ex(request, "paths", &paths_obj);
    int path_count = json_object_array_length(paths_obj);

    for (int i = 0; i < path_count; i++) {
        const char* path = json_object_get_string(json_object_array_get_idx(paths_obj, i));
       
        // Remove trailing slash if present
        char normalized_path[MAX_PATH_LENGTH];
        strncpy(normalized_path, path, MAX_PATH_LENGTH - 1);
        normalized_path[MAX_PATH_LENGTH - 1] = '\0';
       
        size_t path_len = strlen(normalized_path);
        int is_directory = 0;
       
        // Check if path ends with '/'
        if (path_len > 0 && normalized_path[path_len - 1] == '/') {
            is_directory = 1;

            //****************************************** */
            ss->types[i] = is_directory;
            normalized_path[path_len - 1] = '\0';  // Remove trailing slash
            path_len--;
        }

        ss->path_count ++;
        ss->accessible_paths[ss->path_count - 1] = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
        strcpy(ss->accessible_paths[ss->path_count - 1], normalized_path);


        // Split path into components
        char* components[MAX_PATH_LENGTH];
        int component_count;
        parse_path_components(normalized_path, components, &component_count);
       
        if (component_count == 0) {
            // Handle empty path error
            continue;
        }
       
        // Traverse/build the tree
        TreeNode* current = nm->root;
        for (int j = 0; j < component_count; j++) {
            int found = 0;
            for (int k = 0; k < current->child_count; k++) {
                if (strcmp(current->children[k]->name, components[j]) == 0) {
                    current = current->children[k];
                    found = 1;
                    break;
                }
            }
           
            if (!found) {
                // Determine if this component should be a directory
                int should_be_directory = is_directory || (j < component_count - 1);
               
                // Create new node
                TreeNode* new_node = create_tree_node(components[j], should_be_directory);
                if (new_node == NULL) {
                    // Handle memory allocation error
                    for (int cleanup = 0; cleanup < component_count; cleanup++) {
                        free(components[cleanup]);
                    }
                    // Add appropriate error handling here
                    continue;
                }
               
                add_child_node(current, new_node);
                // printf("%s\n", get_node_path(new_node));
                current = new_node;
            } else {
                // If this is the last component and the path ends with '/',
                // ensure the existing node is marked as a directory
                if (j == component_count - 1 && is_directory) {
                    current->is_directory = 1;
                }
            }
        }
       
        // Add server ID to the final node
        //   fprintf(stderr, "coming here!\n");
        add_server_to_node(current, ss->id, 0, -1);
        //   fprintf(stderr, "went here!\n");
        // Clean up components
        for (int j = 0; j < component_count; j++) {
            free(components[j]);
        }
    }

    //****************************** */
    handle_path_replication(ss->id);

    //work
    //thread chalan jo hur 60 sec baad backup krata rhe
    //ab ek thread chalana pdega jo hur 60 sec baad krta rhega change hua kuch to vo krunga dirty bit set

    // Send success response
    json_object* response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_string("success"));
    json_object_object_add(response, "ss_id", json_object_new_int(ss->id)); // tell gaur.

    send_message(client_socket, response);
    json_object_put(response);

    pthread_mutex_unlock(&nm->lock);
    return ss->id - 1;
}

// int find_storage_server_with_path(const char *path) {
//     int num_ss = nm->storage_server_count;
//     fprintf(stderr, "%s\n", path);

//     TreeNode *tmp = lru_cache_get(cache, path);
//     if(tmp == NULL) {
//         tmp = find_node(nm->root, path);
//         if(tmp != NULL)
//             lru_cache_put(cache, path, tmp);
//     }
   
//     if(tmp != NULL) {
//         int mn = INT_MAX;
//         int min_id = -1;
//         for(int i = 0; i < tmp->server_count; i ++) {
//             fprintf(stderr, "%d\n", tmp->storage_servers[i] - 1);
//             if(mn > nm->storage_servers[tmp->storage_servers[i] - 1]->current_load) {
//                 mn = nm->storage_servers[tmp->storage_servers[i] - 1]->current_load;
//                 min_id = nm->storage_servers[tmp->storage_servers[i] - 1]->id;
//             }
//         }
//         return min_id;
//     }
//     return -1;
// }

int is_parent_of_path(TreeNode* node, const char* path) {
    char* node_path = get_node_path(node);
    size_t node_path_len = strlen(node_path);
    int is_parent = strncmp(node_path, path, node_path_len) == 0 && (path[node_path_len] == '/' || path[node_path_len] == '\0');
    free(node_path);
    return is_parent;
}


StorageServer* find_best_storage_server_for_creation(const char* path) {
    if (!path || !nm || !nm->root || !nm->storage_servers) {
        return NULL;
    }

    StorageServer* best_server = NULL;
    int min_load = INT_MAX;
   
    // Split the path into components
    char* components[MAX_PATH_LENGTH];
    int component_count;
    parse_path_components(path, components, &component_count);
   
    // Start from root and traverse down as far as possible
    TreeNode* current = nm->root;
    TreeNode* deepest_match = nm->root;  // Keep track of deepest matching node
   
    for (int i = 0; i < component_count; i++) {
        int found = 0;
        for (int j = 0; j < current->child_count; j++) {
            if (current->children[j] &&
                strcmp(current->children[j]->name, components[i]) == 0) {
                current = current->children[j];
                deepest_match = current;  // Update deepest match
                found = 1;
                break;
            }
        }
        if (!found) {
            break;  // Stop traversing if component not found
        }
    }

    // First try servers directly attached to the deepest matching node
    if (deepest_match->server_count > 0) {
        for (int i = 0; i < deepest_match->server_count; i++) {
            int server_id = deepest_match->storage_servers[i].sid;
            if (server_id <= 0 || server_id > nm->storage_server_count) {
                continue;
            }
           
            StorageServer* ss = nm->storage_servers[server_id - 1];
            if (ss && ss->active && ss->current_load < min_load) {
                min_load = ss->current_load;
                best_server = ss;
            }
        }
       
        // Clean up components before returning if we found a server
        if (best_server) {
            for (int i = 0; i < component_count; i++) {
                free(components[i]);
            }
            return best_server;
        }
    }

    // If no server found at deepest node, traverse up the tree looking for servers
    TreeNode* current_node = deepest_match;
    while (current_node && !best_server) {
        for (int i = 0; i < current_node->server_count; i++) {
            int server_id = current_node->storage_servers[i].sid;
            if (server_id <= 0 || server_id > nm->storage_server_count) {
                continue;
            }
           
            StorageServer* ss = nm->storage_servers[server_id - 1];
            if (ss && ss->active && ss->current_load < min_load) {
                min_load = ss->current_load;
                best_server = ss;
            }
        }
        current_node = current_node->parent;
    }

    // If still no server found, find least loaded active server
    if (!best_server) {
        for (int i = 0; i < nm->storage_server_count; i++) {
            StorageServer* ss = nm->storage_servers[i];
            if (ss && ss->active && ss->current_load < min_load) {
                min_load = ss->current_load;
                best_server = ss;
            }
        }
    }

    // Clean up components
    for (int i = 0; i < component_count; i++) {
        free(components[i]);
    }

    return best_server;
}

char get_first_non_space(const char* str) {
    if (str == NULL) return '\0';
   
    while (*str != '\0') {
        if (*str != ' ') {
            return *str;
        }
        str++;
    }
   
    return '\0'; // No non-space character found
}

int handle_client_request(Client *cl, int client_socket, json_object *request) {
    json_object *req_id;
    json_object_object_get_ex(request, "request_id", &req_id);
    int req_id_client = json_object_get_int(req_id);

    json_object* operation_obj;
    json_object_object_get_ex(request, "operation", &operation_obj);

    fprintf(stderr, "A request from a client on: %s:%d\n", cl->ip, cl->port);

    json_object* initial_ack = json_object_new_object();
    json_object_object_add(initial_ack, "ack", json_object_new_int(1));
    json_object_object_add(initial_ack, "client_id", json_object_new_int(cl->id));
    send_message(client_socket, initial_ack);
    json_object_put(initial_ack);

    const char* operation = json_object_get_string(operation_obj);
    json_object* response = json_object_new_object();
    if(strcmp(operation, "read") == 0 || strcmp(operation, "write") == 0 || strcmp(operation, "stream") == 0 || strcmp(operation, "get_info") == 0) {
        json_object* path_obj;
        json_object_object_get_ex(request, "path", &path_obj);

        const char* path = json_object_get_string(path_obj);

        // int server_with_path = find_storage_server_with_path(path);
        fprintf(stderr, "%s\n", path);
        TreeNode *existing_node = find_node(nm->root, path);
        if (existing_node == NULL) {
            json_object_object_add(response, "status", json_object_new_string("error"));
            json_object_object_add(response, "message", json_object_new_string("no file location found!\n"));
            send_message(client_socket, response);
            json_object_put(response);

            pthread_mutex_unlock(&nm->lock);
            // free(cl);
            return -1;
        }

        //************************************************************************* */
        if(existing_node->only_read == true && strcmp(operation, "write") == 0){
            json_object_object_add(response, "status", json_object_new_string("error"));
            json_object_object_add(response, "message", json_object_new_string("only read operation allowed on this path!\n"));
            send_message(client_socket, response);
            json_object_put(response);

            pthread_mutex_unlock(&nm->lock);
            // free(cl);
            return -1;
        }

        if(existing_node->only_read == true && strcmp(operation, "read") == 0){
            Request p_request;
            p_request.client_associated = cl;

            if(existing_node -> server_count > 1) {
                p_request.server_associated = nm->storage_servers[existing_node->storage_servers[1].sid - 1];
                p_request.reqid = req_id_client;
                p_request.corr_node = existing_node;

                cl->pending_count ++;
                cl->pending_requests[cl->pending_count - 1] = p_request;

                int load = p_request.server_associated->current_load ++;
                p_request.server_associated->processing_requests[load] = p_request;

                char* path = (char*)malloc(sizeof(char) * MAX_PATH_LENGTH);

                json_object_object_add(response, "ip", json_object_new_string(nm->storage_servers[existing_node->storage_servers[1].sid - 1]->ip));
                json_object_object_add(response, "client_port", json_object_new_int(nm->storage_servers[existing_node->storage_servers[1].sid - 1]->client_port));
                json_object_object_add(response, "receive_from_replica", json_object_new_int(nm->storage_servers[existing_node->storage_servers[1].sid - 1]->client_port));
                // json_object_object_add(response, "client_id", json_object_new_int(cl->id - 1));
                send_message(client_socket, response);

                pthread_mutex_unlock(&nm->lock);
                  return cl->id - 1;
            }else {
                json_object_object_add(response, "status", json_object_new_string("error"));
                json_object_object_add(response, "message", json_object_new_string("the requested path is a directory!\n"));
                send_message(client_socket, response);
                json_object_put(response);

                pthread_mutex_unlock(&nm->lock);
                  return -1;
            }   
            // free(cl);
          
        }

        if(existing_node->is_directory == 1) {
            json_object_object_add(response, "status", json_object_new_string("error"));
            json_object_object_add(response, "message", json_object_new_string("the requested path is a directory!\n"));
            send_message(client_socket, response);
            json_object_put(response);

            pthread_mutex_unlock(&nm->lock);
            // free(cl);
            return -1;
        }

        if(strcmp(operation, "get_info") != 0) {
            if(existing_node -> is_written_to == 1) {
                json_object_object_add(response, "status", json_object_new_string("error"));
                json_object_object_add(response, "message", json_object_new_string("file is being written to!\n"));
                send_message(client_socket, response);
                json_object_put(response);

                pthread_mutex_unlock(&nm->lock);
                // free(cl);
                return -1;
            }
        }

        if(strcmp(operation, "write") == 0) {
            existing_node->is_written_to = 1;
        }

        Request p_request;
        p_request.client_associated = cl;
        p_request.server_associated = nm->storage_servers[existing_node->storage_servers[0].sid - 1];
        p_request.reqid = req_id_client;
        p_request.corr_node = existing_node;

        cl->pending_count ++;
        cl->pending_requests[cl->pending_count - 1] = p_request;

        int load = p_request.server_associated->current_load ++;
        p_request.server_associated->processing_requests[load] = p_request;

        json_object_object_add(response, "ip", json_object_new_string(nm->storage_servers[existing_node->storage_servers[0].sid - 1]->ip));
        json_object_object_add(response, "client_port", json_object_new_int(nm->storage_servers[existing_node->storage_servers[0].sid - 1]->client_port));
        // json_object_object_add(response, "client_id", json_object_new_int(cl->id - 1));
        send_message(client_socket, response);
       
        //********************************************** */
        StorageServer* ss = nm->storage_servers[existing_node->storage_servers[0].sid - 1];
        if((ss->backup1 || ss->backup2) && strcmp(operation, "write") == 0){
            ss->pending_backup_paths[ss->pending_backup_cnt] = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
            strcpy(ss->pending_backup_paths[ss->pending_backup_cnt], path);
            ss->types_backup_paths[ss->pending_backup_cnt] = 0;
            ss->pending_backup_cnt++;
        }

    }else    
    if (strcmp(operation, "create") == 0) {
        json_object *path_obj, *name_obj, *check_obj;

        // path has slash at the end.
        json_object_object_get_ex(request, "path", &path_obj);
        const char* path = json_object_get_string(path_obj);

        json_object_object_get_ex(request, "name", &name_obj);
        const char* name = json_object_get_string(name_obj);

        json_object_object_get_ex(request, "is_directory", &check_obj);
        bool is_dir = json_object_get_boolean(check_obj);
       
        char *path1 = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
        char *path2 = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);
        //********************************************** */
        strcpy(path1, "myserver");

        fprintf(stderr, "error comes\n");

        if(get_first_non_space(path) != '/') {
            path1 = strcat(path1, "/");
        }
        path1 = strcat(path1, path);
        path1 = strcat(path1, name);

        if(is_dir == true) {
            path1 = strcat(path1, "/");
        }
        //******** */   ye naya dala h taki success message pe slash se check kr sku ki dir thi ki ni .... gaur ne hi kha h
        // if(is_dir == true){
        //    path1 = strcat(path1, "/");
        // }

        // Handle path creation
        // TreeNode* existing_node = find_node(nm->root, path1);
        TreeNode *existing_node = find_node(nm->root, path1);
        if (existing_node != NULL) {
            json_object_object_add(response, "status", json_object_new_string("error"));
            json_object_object_add(response, "message", json_object_new_string("Path already exists"));
            send_message(client_socket, response);
            json_object_put(response);

            pthread_mutex_unlock(&nm->lock);
            return -1;
        }
       
        StorageServer* best_server = find_best_storage_server_for_creation(path1); // come here  
        if (best_server == NULL) {
            json_object_object_add(response, "status", json_object_new_string("error"));
            json_object_object_add(response, "message", json_object_new_string("No suitable storage server found"));

            send_message(client_socket, response);
            json_object_put(response);
            pthread_mutex_unlock(&nm->lock);
            return -1;
        } else {
            // cl->pending_count ++;
            // cl->pending_requests[cl->pending_count - 1].reqid = req_id_client;
            // cl->pending_requests[cl->pending_count - 1].corr_node = NULL;

            // int c_load = best_server->current_load ++;
            // best_server->processing_requests[c_load] = req_id_client;

            Request p_request;
            p_request.client_associated = cl;
            p_request.server_associated = best_server;
            p_request.reqid = req_id_client;
            p_request.corr_node = NULL;

            cl->pending_count ++;
            cl->pending_requests[cl->pending_count - 1] = p_request;

            int load = p_request.server_associated->current_load ++;
            p_request.server_associated->processing_requests[load] = p_request;

            json_object *request = json_object_new_object();
            json_object_object_add(request, "request_code", json_object_new_string("create_empty"));
            json_object_object_add(request, "request_id", json_object_new_int(req_id_client));
            json_object_object_add(request, "client_id", json_object_new_int(cl->id - 1));
            json_object_object_add(request, "path", json_object_new_string(path1));
            json_object_object_add(request, "type", json_object_new_boolean(is_dir));

            // int ss_sock = create_socket_to_send_to(best_server->ip, best_server->nm_port);
            send_message(best_server->sock, request);
            // json_object_put(request);

            sprintf(path2, "replica_%d/", best_server->id);
            path2 = strcat(path2, path);
            path2 = strcat(path2, name);

           
            // strcpy(best_server->pending_backup_paths[best_server->pending_backup_cnt], path);
            // best_server->types_backup_paths[best_server->pending_backup_cnt] = is_dir;
            // best_server->pending_backup_cnt++;
            json_object *request1 = json_object_new_object();
            json_object_object_add(request1, "request_code", json_object_new_string("create_empty"));
            json_object_object_add(request1, "request_id", json_object_new_int(-1));
            json_object_object_add(request1, "ssid", json_object_new_int(best_server->id)); //1 index manra 
            json_object_object_add(request1, "path", json_object_new_string(path2));
            json_object_object_add(request1, "type", json_object_new_boolean(is_dir));

            sleep(3);
            if(best_server->backup1) send_message(best_server->backup1->sock, request1);
            sleep(2);
            if(best_server->backup2) send_message(best_server->backup2->sock, request1);
            // json_object_put(request1);

            free(path1);
            free(path2);
            // close(ss_sock);
        }
    }
    else if (strcmp(operation, "delete") == 0) {
        json_object *path_obj;
        json_object_object_get_ex(request, "path", &path_obj);

        const char* path = json_object_get_string(path_obj);
        char *path2 = (char *) malloc(sizeof(char) * MAX_PATH_LENGTH);

        // Handle path creation
        TreeNode* existing_node = find_node(nm->root, path);
        // fprintf(stderr, "hello\n");
        // int server_with_path = find_storage_server_with_path(path);
       
        // fprintf("%d\n", server_with_path);

        if (existing_node == NULL) {
            json_object_object_add(response, "status", json_object_new_string("error"));
            json_object_object_add(response, "message", json_object_new_string("No server with the path found!"));
            send_message(client_socket, response);
            json_object_put(response);

            pthread_mutex_unlock(&nm->lock);
            return -1;
        }

        int enode_server = existing_node->storage_servers[0].sid - 1;
        fprintf(stderr, "%d\n", enode_server);


        sprintf(path2, "replica_%d/", enode_server + 1);
        path2 = strcat(path2, path);

        Request p_request;
        p_request.client_associated = cl;
        p_request.server_associated = nm->storage_servers[enode_server];
        p_request.reqid = req_id_client;
        p_request.corr_node = existing_node;

        cl->pending_count ++;
        cl->pending_requests[cl->pending_count - 1] = p_request;

        if(p_request.server_associated == NULL) {
            fprintf(stderr, "bye\n");
        }
        fprintf(stderr, "%d\n", nm->storage_servers[enode_server]->id);
        fprintf(stderr, "%d\n", nm->storage_servers[enode_server]->current_load);
        int load = p_request.server_associated->current_load ++;
        
        p_request.server_associated->processing_requests[load] = p_request;
       


        char *pth = (char *) malloc(sizeof(char) * MAX_FILENAME_LENGTH);
        strcpy(pth, "myserver/");
        strcat(pth, path);

        json_object *request = json_object_new_object();
        json_object_object_add(request, "request_id", json_object_new_int(req_id_client));
        json_object_object_add(request, "request_code", json_object_new_string("delete"));
        json_object_object_add(request, "client_id", json_object_new_int(cl->id - 1));
        json_object_object_add(request, "path", json_object_new_string(pth));

        // int ss_sock = create_socket_to_send_to(nm->storage_servers[server_with_path]->ip, nm->storage_servers[server_with_path]->nm_port);
        // send_message(ss_sock, request);
        // json_object_put(request);
        send_message(nm->storage_servers[enode_server]->sock, request);
        // json_object_put(request);

        json_object *request_2 = json_object_new_object();
        json_object_object_add(request_2, "request_id", json_object_new_int(-1));
        json_object_object_add(request_2, "request_code", json_object_new_string("delete"));
        json_object_object_add(request_2, "path", json_object_new_string(path2));

        StorageServer* ss = nm->storage_servers[enode_server];

        sleep(3);
        if(ss->backup1) send_message(ss->backup1->sock, request_2);
        sleep(2);
        if(ss->backup2) send_message(ss->backup2->sock, request_2);
        // json_object_put(request);
       

        // json_object *response1;
        // response1 = receive_request(nm->storage_servers[server_with_path - 1]->sock);

        // json_object* status_obj;
        // if (json_object_object_get_ex(response1, "status", &status_obj)) {
        //     const char* status = json_object_get_string(status_obj);
        //     printf("Storage Server response: %s\n", status);

        //     if(strcmp(status, "success") == 0) {
        //         json_object_object_add(response, "status", json_object_new_string("success"));
        //     }else if(strcmp(status, "failure") == 0) {
        //         json_object *msg;
        //         json_object_object_get_ex(response1, "error", &msg);
        //         printf("%s\n", json_object_get_string(msg));
        //         json_object_object_add(response, "status", json_object_new_string("error"));
        //     }
        // }

        // json_object_put(response1);
        // close(ss_sock);
       
    }
    else if (strcmp(operation, "copy") == 0) {
        json_object *path_obj1, *path_obj2;
        json_object_object_get_ex(request, "path1", &path_obj1);
        json_object_object_get_ex(request, "path2", &path_obj2);

        const char* path1 = json_object_get_string(path_obj1);
        const char* path2 = json_object_get_string(path_obj2);

        // Handle path creation
        // TreeNode* existing_node = find_node(nm->root, path);
        // int source_server = find_storage_server_with_path(path1);
        TreeNode *source_node = find_node(nm->root, path1);
        if (source_node == NULL) {
            json_object_object_add(response, "status", json_object_new_string("error"));
            json_object_object_add(response, "message", json_object_new_string("No server with the source path found!"));
            send_message(client_socket, response);
            json_object_put(response);

            pthread_mutex_unlock(&nm->lock);
            // free(cl);
            return -1;
        }
        fprintf(stderr, "hello\n");

        TreeNode *dest_node = find_node(nm->root, path2);
        if (dest_node == NULL) {
            json_object_object_add(response, "status", json_object_new_string("error"));
            json_object_object_add(response, "message", json_object_new_string("No server with the dest path found!"));
            send_message(client_socket, response);
            json_object_put(response);

            pthread_mutex_unlock(&nm->lock);
            // free(cl);
            return -1;
        }
     
        int dnode = dest_node->storage_servers[0].sid - 1;
        int snode = source_node->storage_servers[0].sid - 1;

        Request p_request;
        p_request.client_associated = cl;
        p_request.server_associated = nm->storage_servers[dnode];
        p_request.reqid = req_id_client;
        p_request.corr_node = dest_node;

        cl->pending_count ++;
        cl->pending_requests[cl->pending_count - 1] = p_request;

        int load = p_request.server_associated->current_load ++;
        p_request.server_associated->processing_requests[load] = p_request;
       
        json_object *request = json_object_new_object();
        json_object_object_add(request, "request_code", json_object_new_string("copy"));
        json_object_object_add(request, "request_id", json_object_new_int(req_id_client));
        json_object_object_add(request, "client_id", json_object_new_int(cl->id - 1));
        json_object_object_add(request, "destination_path", json_object_new_string(path2));


        json_object_object_add(request, "storage_ip", json_object_new_string(nm->storage_servers[snode]->ip));
        json_object_object_add(request, "storage_port", json_object_new_int(nm->storage_servers[snode]->client_port));
        json_object_object_add(request, "storage_path", json_object_new_string(path1));
        json_object_object_add(request, "ssid", json_object_new_int(snode + 1));

        // int ss_sock = create_socket_to_send_to(nm->storage_servers[dest_server]->ip, nm->storage_servers[dest_server]->nm_port);
        // send_message(ss_sock, request);
        // json_object_put(request);

        fprintf(stderr, "hello\n");

        send_message(nm->storage_servers[dnode]->sock, request);
        json_object_put(request);
       
        size_t path_len = strlen(path2);
        int is_directory = 0;
       
        // Check if path ends with '/'
        if (path_len > 0 && path2[path_len - 1] == '/') {
            is_directory = 1;
        }

        StorageServer* ss = nm->storage_servers[dnode];
        if(ss->backup1 || ss->backup2){
            strcpy(ss->pending_backup_paths[ss->pending_backup_cnt], path1);
            ss->types_backup_paths[ss->pending_backup_cnt] = is_directory;
            ss->pending_backup_cnt++;
        }
    }else if(strcmp(operation, "list_all") == 0) {
        json_object* paths_array = json_object_new_array();
        build_path_list(nm->root, "", paths_array);
       
        json_object_object_add(response, "status", json_object_new_string("success"));
        json_object_object_add(response, "paths", paths_array);
       
        send_message(client_socket, response);
    }
}

int handle_client_connection(int client_socket, json_object* request) {
    pthread_mutex_lock(&nm->lock);
   
    json_object *ip_object, *port_object;
    if(json_object_object_get_ex(request, "client_ip", &ip_object)) {
       
    }else {
        fprintf(stderr, "client_ip not found!\n");
    }

    if(json_object_object_get_ex(request, "client_port", &port_object)) {

    }else {
        fprintf(stderr, "client_port not found!\n");
    }
   
    Client* cl;
    bool is_found_in_queue = false;
    for(int i = 0; i < nm->client_count; i ++) {
        if(nm->clients_in_queue[i] == NULL) continue;
        if(strcmp(nm->clients_in_queue[i]->ip, json_object_get_string(ip_object)) == 0 && nm->clients_in_queue[i]->port == json_object_get_int(port_object)) {
            cl = nm->clients_in_queue[i];
            is_found_in_queue = true;
            break;
        }
    }

    if(!is_found_in_queue) {
        cl = (Client*)malloc(sizeof(Client));
        strcpy(cl->ip, json_object_get_string(ip_object));
       
        cl->port = json_object_get_int(port_object);
        cl->pending_count = 0;

        bool is_found = false;
        for(int i = 0; i < nm->client_count; i ++) {
            if(nm->clients_in_queue[i] == NULL) {
                cl->id = i + 1;
                nm->clients_in_queue[i] = cl;
                is_found = true;
                break;
            }  
        }
        if(!is_found) {
            cl->id = nm->client_count + 1;
            nm->client_count ++;
            nm->clients_in_queue[nm->client_count - 1] = cl;
        }
    }

    cl->sock = client_socket;
    pthread_mutex_unlock(&nm->lock);  
    return cl->id - 1;
}

int create_socket_to_send_to(const char* ip_address, int port) {
    // Create socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Initialize server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, ip_address, &server_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        close(client_socket);
        return -1;
    }

    // Connect to server
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_socket);
        return -1;
    }

    return client_socket;
}

// Helper function to send response
int send_message(int socket, json_object* msg) {
    const char* json_str = json_object_to_json_string(msg);
    fprintf(stderr, "%s\n", json_str);
    uint32_t length = strlen(json_str);
    uint32_t network_length = htonl(length);
   
    if(send(socket, &network_length, sizeof(network_length), 0) == -1) {
        return -1;
    }

    if(send(socket, json_str, length, 0) == -1) {
        return -1;
    }
}
char* get_current_time() {
    static char time_str[9]; // "HH:MM:SS\0"
    time_t now;
    struct tm *tm_now;

    time(&now);
    tm_now = localtime(&now);
   
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_now);
   
    return time_str;
}

// Helper function to receive request
json_object* receive_request(int socket) {
    uint32_t length;
    if (recv(socket, &length, sizeof(length), 0) <= 0) {
        return NULL;
    }
    length = ntohl(length);

    char* buffer = (char*)malloc(length + 1);
    int total_received = 0;
    while (total_received < length) {
        int received = recv(socket, buffer + total_received, length - total_received, 0);
        if (received <= 0) {
            free(buffer);
            return NULL;
        }
        total_received += received;
    }
    buffer[length] = '\0';
    fprintf(stderr, "%s\n", buffer);
   
    char log_string[length];
    sprintf(log_string, "%s: %s\n", get_current_time(), buffer);
    write(fd_log, log_string, strlen(log_string));

    json_object* request = json_tokener_parse(buffer);
    free(buffer);
    return request;
}

// Cleanup function
void cleanup_naming_server() {
    pthread_mutex_lock(&nm->lock);
    free_tree_node(nm->root);
    for (int i = 0; i < nm->storage_server_count; i++) {
        StorageServer* ss = nm->storage_servers[i];
        for (int j = 0; j < ss->path_count; j++) {
            free(ss->accessible_paths[j]);
        }
        // free(ss->accessible_paths);
        free(ss);
    }

    for (int i = 0; i < nm->client_count; i++) {
        Client* cl = nm->clients_in_queue[i];
        free(cl);
    }
   
    pthread_mutex_unlock(&nm->lock);
    pthread_mutex_destroy(&nm->lock);
    close(nm->server_socket);
}

int main(int argc, char* argv[]) {
    fd_log = open("log.txt", O_CREAT | O_RDWR | O_TRUNC, 0655);
    if(fd_log == -1) {
        fprintf(stderr, "couldn't open the log file!\n");
        return 0;
    }

    initialize_naming_server();
    fprintf(stderr, "hello\n");
    // Create server socket
    nm->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (nm->server_socket < 0) {
        perror("Socket creation failed");
        return 1;
    }

     fprintf(stderr, "hello\n");

    // Set socket options
    int opt = 1;
    if (setsockopt(nm->server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        return 1;
    }
    fprintf(stderr, "hello\n");

    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(argc > 1 ? atoi(argv[1]) : 0);

    fprintf(stderr, "hello\n");

    // Bind
    if (bind(nm->server_socket, (struct sockaddr*)&server_addr,
        sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    // Get the assigned port if using port 0
    socklen_t len = sizeof(server_addr);
    if (getsockname(nm->server_socket, (struct sockaddr*)&server_addr, &len) < 0) {
        perror("Getsockname failed");
        return 1;
    }
    fprintf(stderr, "hello\n");

    printf("%s\n", get_local_ip());
    printf("Naming Server started on port %d\n", ntohs(server_addr.sin_port));

    // Listen
    if (listen(nm->server_socket, 100) < 0) {
        perror("Listen failed");
        return 1;
    }

    // Accept connections
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
       
        int* client_socket = malloc(sizeof(int));
        *client_socket = accept(nm->server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (*client_socket < 0) {
            perror("Accept failed");
            free(client_socket);
            continue;
        }

        pthread_t thread;
        fprintf(stderr, "hello\n");
        if (pthread_create(&thread, NULL, handle_connection, client_socket) != 0) {
            perror("Thread creation failed");
            close(*client_socket);
            free(client_socket);
            continue;
        }
        pthread_detach(thread);
    }

    cleanup_naming_server();
    // close(fd_log);
    return 0;
}

