import numpy as np
import queue
from operator import itemgetter
import heapq as hq
import re
from typing import Dict
from collections import defaultdict
import subprocess
import heapq
inputFun = input

class Node:
    """Class to represent each node (input, output, gate) in the circuit."""

    def __init__(self, name, node_type, inputs=dict()):
        self.name = name
        self.node_type = node_type
        self.inputs: dict = inputs
        self.outputs: dict = dict()
        self.topo_index = -1

    def add_output(self, output_nodes):
        """Adds an output node to the outputs list."""
        self.outputs = output_nodes

    def __repr__(self):
        return f"Node(name='{self.name}', type='{self.node_type}', inputs={self.inputs}, outputs={self.outputs})"


class Circuit:
    """Class to represent the entire circuit."""

    def __init__(self, file_path, is_trojan=False):
        self.file_path = file_path
        self.nodes: Dict[str, Node] = dict()
        self.pis = dict()
        self.pos = dict()
        self.digraph = dict()
        self.topology_order = dict()
        self.topology_list = list()
        self.piIdx = dict()
        self.node_cc1 = dict()
        self.node_cc0 = dict()
        self.node_co = dict()
        self.rare_zero = dict()
        self.rare_one = dict()
        self.rare_CISCO: Dict[str, set] = dict()
        self.rare_partail_nodes_zero = dict()
        self.rare_partail_nodes_one = dict()
        self.control_input: Dict[str, set] = dict()
        self.control_output: Dict[str, set] = dict()
        self.avg_cc = 0
        self.avg_co = 0
        self.payload_TFO = dict()
        self.dependency_mask:np.ndarray = None
        if is_trojan:
            if ".v" in file_path:
                prefix = file_path.replace(".v", "") 
                abc_command = f"./abc -c \"read_library yc.genlib; read -m {file_path}; strash; resyn2; write_bench -l {prefix}_strash.bench\""
            else:
                prefix = file_path.replace(".bench", "")
                abc_command = f"./abc -c \"read_library yc.genlib; read {file_path}; strash; resyn2; write_bench -l {prefix}_strash.bench\""
            try:
                subprocess.run(abc_command, shell=True, check=True,
                            capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"ABC strash failed: {e.stderr}")
            file_path = f"{prefix}_strash.bench"
        if ".v" in file_path:
            self.parse_verilog_file(file_path)
        else:
            self.parse_bench_file(file_path)

        self.pi_size = len(self.pis)
        self.po_size = len(self.pos)
        self.node_size = len(self.nodes)
        # print("pi_size", self.pi_size,"po_size", self.po_size, "node_size", self.node_size)

        print("file_path", file_path)
        print("pi_size", self.pi_size, "po_size",
              self.po_size, "node_size", self.node_size)

        self.ob_threshold = 0.004
        self.low_ob_node = []
        self.rare_threshold = 0.1
        self.rare_target_threshold = 0.001
        self.pattern_num = 10000
        self.current_input_pattern = np.random.choice(
            [False, True], self.pi_size)

        # print("is_cyclic", self.is_cyclic())
        self.topology_sort()
        print("topology_sort done.")
        # print(self.topology_list)
        if is_trojan:
            self.get_control_input()
            self.get_control_output()
        self.scoap(self.ob_threshold)
        print("scoap done.")
        self.zero_size = dict.fromkeys(self.nodes, 0.0)
        self.one_size = dict.fromkeys(self.nodes, 0.0)
        self.rare_wire(self.rare_threshold, self.pattern_num)
        print("rare_wire done.")
        # self.createDependencyMask()
        self.rare_node_name = list(
            self.rare_one.keys()) + list(self.rare_zero.keys())
        if is_trojan:
            self.get_rare_target(self.rare_target_threshold)
            if len(self.rare_target) == 0:
                print("No rare target.")
        self.piIdx = {key: index for index, key in enumerate(self.topology_list)}

    def add_node(self, node):
        """Adds a node to the circuit."""
        self.nodes[node.name] = node

    def parse_bench_file(self, file_path):
        """Parses the circuit file."""
        with open(file_path, 'r') as file:
            for line in file:
                line = line.replace(" ", "")  # replacing space
                line = line.replace("\n", "")
                if line and not line.startswith('#'):
                    self.parse_bench_line(line)
        self.update_outputs()

    def parse_bench_line(self, line):
        """Parses a line from the file and adds the node to the circuit."""
        if line.startswith("INPUT"):
            # Example: INPUT(33)
            node_type, name = line.split('(')
            name = name[:-1]  # Removing closing parenthesis
            self.add_node(Node(name, "pi"))
            self.pis[name] = True

        elif line.startswith("OUTPUT"):
            node_type, name = line.split('(')
            name = name[:-1]  # Removing closing parenthesis
            # self.add_node(Node(name, "po")) #po is a gate
            self.pos[name] = True
        else:
            parts = line.split('=')
            if len(parts) == 2:
                name, details = parts
                if details == "vdd":
                    gate_type = "NOT" 
                    inputs = [next(iter(self.pis))]
                    temp_list = [True] * len(inputs)
                    self.add_node(Node(name + "inv", gate_type.lower(),
                                dict(zip(inputs, temp_list))))
                    for input_node in inputs:
                        self.add_output_connection(input_node, name + "inv")
                        
                    
                    gate_type = "OR"
                    inputs = [next(iter(self.pis)), name + "inv"]
                    temp_list = [True] * len(inputs)
                    self.add_node(Node(name, gate_type.lower(),
                                dict(zip(inputs, temp_list))))
                    for input_node in inputs:
                        self.add_output_connection(input_node, name)
                        
                else:
                    gate_type, inputs = details.split('(')
                    # Removing closing parenthesis and splitting
                    inputs = inputs[:-1].split(',')
                    temp_list = [True] * len(inputs)
                    self.add_node(Node(name, gate_type.lower(),
                                dict(zip(inputs, temp_list))))
                    for input_node in inputs:
                        self.add_output_connection(input_node, name)
            else:
                print("!!!a line goes wrong when parsing.!!!", line)

    def parse_verilog_file(self, file_path):
        """Parses the circuit file."""
        with open(file_path, 'r') as file:
            combined_lines = ""
            for line in file:
                # line = line.replace(" ","") #replacing space
                line = line.replace("\n", "")
                line = line.strip()
                if not line.startswith('//'):
                    if line.endswith(';'):
                        combined_lines = combined_lines + line.strip(";")
                        self.parse_verilog_line(combined_lines)
                        combined_lines = ""
                    else:
                        combined_lines = combined_lines + line

        self.update_outputs()

    def parse_verilog_line(self, line):
        # print(line)
        """Parses a line from the file and adds the node to the circuit."""
        if line.startswith("module") or line.startswith("wire"):
            return
        elif line.startswith("input"):
            line = line.replace("input", '')
            line = line.replace(" ", '')
            inputs = line.split(',')
            # print(inputs)
            for name in inputs:
                self.add_node(Node(name, "pi"))
                self.pis[name] = True

        elif line.startswith("output"):
            line = line.replace("output", '')
            line = line.replace(" ", '')
            outputs = line.split(',')
            for name in outputs:
                self.pos[name] = True
        else:
            inputs = []
            instance_pattern = re.compile(r'(\w+)\s+(\w+)\s*\(([^;]+)\)')
            match = instance_pattern.match(line.strip())

            if match:
                gate_type = match.group(1)
                connections = match.group(3)

            gate_type = re.sub(r'\d+$', '', gate_type)
            connection_pattern = re.compile(r'\.(\w+)\((\w+)\)')
            connection_matches = connection_pattern.findall(connections)

            for port, net in connection_matches:
                if port == "Y":
                    name = net
                else:
                    inputs.append(net)

            if gate_type == "zero":
                first_pi = next(iter(self.pis))
                gate_type = "NAND"
                inputs = [first_pi, first_pi]

            elif gate_type == "one":
                first_pi = next(iter(self.pis))
                gate_type = "AND"
                inputs = [first_pi, first_pi]

            temp_list = [True] * len(inputs)
            self.add_node(Node(name, gate_type.lower(),
                          dict(zip(inputs, temp_list))))
            for input_node in inputs:
                self.add_output_connection(input_node, name)

    def add_output_connection(self, input_node, output_node):
        """Adds an output connection to the temporary structure."""
        if input_node not in self.digraph:
            self.digraph[input_node] = dict()
        self.digraph[input_node][output_node] = True

    def update_outputs(self):
        """Updates the outputs of all nodes based on the temporary structure."""
        for input_node, outputs in self.digraph.items():
            if input_node in self.nodes:
                self.nodes[input_node].add_output(outputs)
            else:
                print("!!!temp_output_connections has a wrong data.!!!", input_node)

    def is_cyclic_util(self, node, visited, recursion_stack):
        visited[node] = True
        recursion_stack[node] = True

        for neighbour in self.nodes[node].outputs:
            if not visited[neighbour]:
                if self.is_cyclic_util(neighbour, visited, recursion_stack):
                    return True
            elif recursion_stack[neighbour]:
                return True

        recursion_stack[node] = False
        return False

    def is_cyclic(self):
        visited = {node: False for node in self.nodes}
        recursion_stack = {node: False for node in self.nodes}

        for node in self.nodes:
            if not visited[node]:
                if self.is_cyclic_util(node, visited, recursion_stack):
                    return True

        return False

    def topology_sort(self):
        in_degree = {}
        q = queue.Queue()
        for name in self.nodes:
            node = self.nodes[name]
            degree = len(node.inputs)
            in_degree[node.name] = degree
            if degree == 0:
                q.put(node.name)

        i = 0
        while not q.empty():
            name = q.get()
            self.topology_order[name] = None
            self.nodes[name].topo_index = i
            i = i + 1
            for output in self.nodes[name].outputs:
                in_degree[output] = in_degree[output] - 1
                if in_degree[output] == 0:
                    q.put(output)
        self.topology_list = list(self.topology_order.keys())
        if len(self.topology_list) != len(self.nodes):
            print("!!!The circuit is cyclic!!!")


    def simulator(self, input_pattern):
        self.current_input_pattern = input_pattern

        topology_order = self.topology_order
        nodes = self.nodes
        pis = self.pis
        pos = self.pos
        po_size = self.po_size

        pq = []
        in_queue = set()

        for pi, new_val in zip(pis, input_pattern):
            if topology_order[pi] != new_val:
                topology_order[pi] = new_val
                for out in nodes[pi].outputs:
                    if out not in in_queue:
                        heapq.heappush(pq, (nodes[out].topo_index, out))
                        in_queue.add(out)

        gate_ops = {
            "and": all,
            "or": any,
            "nand": lambda inputs: not all(inputs),
            "nor": lambda inputs: not any(inputs),
            "xor": lambda inputs: (sum(inputs) % 2 == 1),
            "xnor": lambda inputs: (sum(inputs) % 2 == 0),
            "not": lambda inputs: not inputs[0],
            "buff": lambda inputs: inputs[0],
        }

        while pq:
            _, node_name = heapq.heappop(pq)
            in_queue.discard(node_name)
            node = nodes[node_name]
            node_type = node.node_type

            if node.inputs:
                old_value = topology_order[node_name]
                input_values = [topology_order[inp] for inp in node.inputs]

                if node_type in {"not", "buff"} and len(input_values) != 1:
                    print(f"Warning: {node_type} gate '{node_name}' 期望 1 個輸入，但實際有 {len(input_values)} 個")

                if node_type in gate_ops:
                    new_value = gate_ops[node_type](input_values)
                    if new_value != old_value:
                        topology_order[node_name] = new_value
                        for out in node.outputs:
                            if out not in in_queue:
                                heapq.heappush(pq, (nodes[out].topo_index, out))
                                in_queue.add(out)
                else:
                    print(f"Unknown gate type '{node_type}' in node '{node_name}'")
            elif node_type != "pi":
                print(f"Warning: Node '{node_name}' of type '{node_type}' has no inputs and is not a primary input")

        if po_size == 1:
            return [topology_order[next(iter(pos))]]
        else:
            return [topology_order[k] for k in pos]



    def get_control_input(self):
        for name in self.pis:
            self.control_input[name] = {name}
        for name in self.topology_order:
            for output in self.nodes[name].outputs:
                if output not in self.control_input:
                    self.control_input[output] = self.control_input[name]
                else:
                    self.control_input[output] = self.control_input[output].union(self.control_input[name])
                    
    def get_control_output(self):
        for name in self.pos:
            self.control_output[name] = {name}
        for name in reversed(self.topology_order):
            for input in self.nodes[name].inputs:
                if input not in self.control_output:
                    self.control_output[input] = self.control_output[name]
                else:
                    self.control_output[input] = self.control_output[input].union(self.control_output[input])
                    
    def createDependencyMask(self):
        self.dependency_mask = np.zeros((len(self.nodes), len(self.nodes)))
        for idx in range(len(self.topology_list)):
            name = self.topology_list[idx]
            self.dependency_mask[idx][idx] = 1
            for output in self.nodes[name].outputs:
                self.dependency_mask[self.nodes[output].topo_index] = np.logical_or(self.dependency_mask[self.nodes[output].topo_index], self.dependency_mask[idx]) 
                
    def get_rare_target(self, rare_threshold):
        self.rare_nodes = dict()
        for name, value in self.rare_one.items():
            self.rare_nodes[name] = value
        for name, value in self.rare_zero.items():
            self.rare_nodes[name] = -value
        self.rare_target = self.rare_node_name
        
        self.rare_target = sorted(self.rare_target, key=lambda x: (abs(self.rare_nodes[x]), -int(self.topology_order[x])))
        
        self.rare_target = list(filter(lambda x: abs(self.rare_nodes[x]) < rare_threshold, self.rare_target))
        qu = queue.Queue()
        visited = dict()
        # remove sub rare target
        for name in self.rare_target:
            qu.put(name)
        while not qu.empty():
            name = qu.get()
            for input in self.nodes[name].inputs.keys():
                if input in self.rare_target:
                    self.rare_target.remove(input)
                visited[input] = True
                if input not in visited:
                    qu.put(input)
        
        self.rare_target_input : Dict[str, list] = defaultdict(list)
        def getRareValue(name):
            return min(self.one_size[name], self.zero_size[name])
        dont_care = []
        new_target = []
        for target in self.rare_target:
            goal: dict[str, bool] = dict()
            visited:dict = dict()
            qu = queue.Queue()
            goal[target] = 1 if target in self.rare_one else 0
            def dividNonFix(current_target, non_fix_list):
                fix_control_input_set: dict[str, int] = defaultdict(int)
                pq: queue.PriorityQueue = queue.PriorityQueue()
                for item in non_fix_list:
                    pq.put((-self.nodes[item].topo_index, item))
                    for control in self.control_input[item]:
                        fix_control_input_set[control] += 1
                checkSubNode: queue.PriorityQueue = queue.PriorityQueue()
                checkSubNodeDict: dict = dict()
                conflict_node: dict = dict()
                while not pq.empty() or not checkSubNode.empty():
                    while not checkSubNode.empty() and (pq.empty() or abs(pq.queue[0][0]) < abs(checkSubNode.queue[0][0])):
                        update_name = checkSubNode.queue[0][1]
                        update_top_idx = self.nodes[update_name].topo_index
                        partial_goal = checkSubNode.queue[0][2]
                        conflict = False
                        checkSubNodeDict.pop(update_name)
                        if update_name in conflict_node:
                            conflict = True
                        while not checkSubNode.empty() and abs(checkSubNode.queue[0][0]) == update_top_idx:
                            _, name, current_goal = checkSubNode.get()
                            if current_goal != partial_goal:
                                conflict = True
                        if not conflict:
                            dependecy_sum = itemgetter(
                        *(self.control_input[update_name]))(fix_control_input_set)
                            if isinstance(dependecy_sum, tuple):
                                dependecy_sum = sum(dependecy_sum)
                            goal[update_name] = partial_goal
                            # print("non-conflict:", target, update_name, getRareValue(update_name), dependecy_sum, len(checkSubNode.queue))
                            if dependecy_sum == len(self.control_input[update_name]):
                                if getRareValue(update_name) < 0.1:
                                    # print("get rare input from single", update_name)
                                    getRareInputFromSingle(current_target, update_name)
                                else:
                                    # print("add new lock:", current_target, update_name, partial_goal)
                                    self.rare_target_input[current_target].append((update_name, partial_goal))
                            else:
                                pq.put((-update_top_idx, update_name))
                        else:
                            # print("conflict:", target, update_name)
                            pass
                    if pq.empty():
                        break
                    _, name = pq.get()
                    if self.nodes[name].node_type != 'xor' and self.nodes[name].node_type != 'xnor':
                        for control in self.control_input[name]:
                            fix_control_input_set[control] -= 1
                        for input in self.nodes[name].inputs.keys():
                            if (self.nodes[name].node_type == 'and' and goal[name] == 1) or \
                                (self.nodes[name].node_type == 'nand' and goal[name] == 0) or \
                                (self.nodes[name].node_type == 'nor' and goal[name] == 0) or \
                                (self.nodes[name].node_type == 'or' and goal[name] == 1):
                                if input not in goal or goal[input] == 1:
                                    if input not in checkSubNodeDict:
                                        checkSubNodeDict[input] = 1
                                        checkSubNode.put((-self.nodes[input].topo_index, input, 1))
                                        for control in self.control_input[input]:
                                            fix_control_input_set[control] += 1
                                    elif checkSubNodeDict[input] == 1:
                                        checkSubNode.put((-self.nodes[input].topo_index, input, 1))
                                    else:
                                        conflict_node[input] = True
                                else:
                                    # print("conflict:", target, input, 1)
                                    pass
                            elif (self.nodes[name].node_type == 'or' and goal[name] == 0) or \
                                (self.nodes[name].node_type == 'nor' and goal[name] == 1) or \
                                (self.nodes[name].node_type == 'and' and goal[name] == 0) or \
                                (self.nodes[name].node_type == 'nand' and goal[name] == 1):
                                if input not in goal or goal[input] == 0:
                                    if input not in checkSubNodeDict:
                                        checkSubNodeDict[input] = 0
                                        checkSubNode.put((-self.nodes[input].topo_index, input, 0))
                                        for control in self.control_input[input]:
                                            fix_control_input_set[control] += 1
                                    elif checkSubNodeDict[input] == 0:
                                        checkSubNode.put((-self.nodes[input].topo_index, input, 0))
                                    else:
                                        conflict_node[input] = True
                                else:
                                    # print("conflict:", target, input, 0)
                                    pass
                            elif self.nodes[name].node_type == 'not':
                                if input not in goal or goal[input] == (not goal[name]):
                                    if input not in checkSubNodeDict:
                                        checkSubNodeDict[input] = not goal[name]
                                        checkSubNode.put((-self.nodes[input].topo_index, input, not goal[name]))
                                        for control in self.control_input[input]:
                                            fix_control_input_set[control] += 1
                                    elif checkSubNodeDict[input] == (not goal[name]):
                                        checkSubNode.put((-self.nodes[input].topo_index, input, not goal[name]))
                                    else:
                                        conflict_node[input] = True
                                else:
                                    # print("conflict:", target, input, not goal[name])
                                    pass
                            elif self.nodes[name].node_type == 'buff' or self.nodes[input].node_type == "pi":
                                if input not in goal or goal[input] ==  goal[name]:
                                    if input not in checkSubNodeDict:
                                        checkSubNodeDict[input] = goal[name]
                                        checkSubNode.put((-self.nodes[input].topo_index, input, goal[name]))
                                        for control in self.control_input[input]:
                                            fix_control_input_set[control] += 1
                                    elif checkSubNodeDict[input] == goal[name]:
                                        checkSubNode.put((-self.nodes[input].topo_index, input, goal[name]))
                                    else:
                                        conflict_node[input] = True
                                else:
                                    # print("conflict:", target, input, goal[input])
                                    pass
                            else:
                                print("Not implement node type: ", self.nodes[name].node_type, goal[name])
                                assert(False)
            def getRareInputFromSingle(current_target, target):
                if target in visited:
                    return
                else:
                    visited[target] = True
                qu = queue.Queue()
                qu.put(target)
                while not qu.empty():
                    name = qu.get()
                    if self.nodes[name].node_type == "pi":
                        self.rare_target_input[current_target].append((name, goal[name]))
                        continue
                    elif (self.nodes[name].node_type == 'xor' or self.nodes[name].node_type == 'xnor'):
                        self.rare_target_input[current_target].append((name, goal[name]))
                        continue
                    elif (self.nodes[name].node_type == 'and' and goal[name] == 0) or \
                        (self.nodes[name].node_type == 'nor' and goal[name] == 0):
                        self.rare_target_input[current_target].append((name, goal[name]))
                        continue
                    elif (self.nodes[name].node_type == 'or' and goal[name] == 1) or \
                            (self.nodes[name].node_type == 'nand' and goal[name] == 1):
                        self.rare_target_input[current_target].append((name, goal[name]))
                        continue
                    for input in self.nodes[name].inputs.keys():
                        if (self.nodes[name].node_type == 'and' and goal[name] == 1) or \
                            (self.nodes[name].node_type == 'nand' and goal[name] == 0):
                            if input not in goal or goal[input] == 1:
                                goal[input] = 1
                            else:
                                print("Don't care:", target)
                                dont_care.append(target)
                                return
                        elif (self.nodes[name].node_type == 'or' and goal[name] == 0) or \
                            (self.nodes[name].node_type == 'nor' and goal[name] == 1):
                            if input not in goal or goal[input] == 0:
                                goal[input] = 0
                            else:
                                print("Don't care:", target)
                                dont_care.append(target)
                                return
                        elif self.nodes[name].node_type == 'not':
                            if input not in goal or goal[input] != goal[name]:
                                goal[input] = int(not goal[name])
                            else:
                                print("Don't care:", target)
                                dont_care.append(target)
                                return
                        elif self.nodes[name].node_type == 'buff':
                            if input not in goal or goal[input] == goal[name]:
                                goal[input] = goal[name]
                            else:
                                print("Don't care:", target)
                                dont_care.append(target)
                                return
                        else:
                            print("Not implement node type: ", self.nodes[name].node_type, goal[name])
                            assert(False)
                        qu.put(input)
                non_fix_list:set = set()
                for item in self.rare_target_input[current_target]:
                    if len(self.control_input[item[0]]) != 1 and (self.nodes[item[0]].node_type != 'xor' and self.nodes[item[0]].node_type != 'xnor'):
                        non_fix_list.add(item[0])
                if current_target == target:
                    current_target = f"non_fix_{target}"
                dividNonFix(current_target, list(non_fix_list))
            getRareInputFromSingle(target, target)
            self.rare_target_input[target] = list(set(self.rare_target_input[target]))
            self.rare_target_input[target] = sorted(self.rare_target_input[target], key=lambda x: (getRareValue(x[0]), -len(self.control_input[x[0]])))
            if len(self.rare_target_input[f"non_fix_{target}"]) != 0:
                new_target.append(f"non_fix_{target}")
                self.rare_target_input[f"non_fix_{target}"].extend(self.rare_target_input[target])
                self.rare_target_input[f"non_fix_{target}"] = sorted(self.rare_target_input[f"non_fix_{target}"], key=lambda x: (getRareValue(x[0]), -len(self.control_input[x[0]])))
            else:
                self.rare_target_input.pop(f"non_fix_{target}")
            
        for node in dont_care:
            if node in self.rare_target:
                self.rare_target.remove(node)
                    
        for target in self.rare_target:
            self.rare_CISCO[target] = set()
            for co in self.control_output[target]:
                self.rare_CISCO[target] = self.rare_CISCO[target].union(self.control_input[co])
        
        self.rare_target.extend(new_target)
                
    def scoap(self, ob_threshold):
        # controlability
        for name in self.topology_order:
            self.node_co[name] = 0
            input_cc0 = []
            input_cc1 = []
            if len(self.nodes[name].inputs) != 0:

                if (len(self.nodes[name].inputs.keys()) == 1):
                    input_cc0.append(itemgetter(
                        *(self.nodes[name].inputs.keys()))(self.node_cc0))
                    input_cc1.append(itemgetter(
                        *(self.nodes[name].inputs.keys()))(self.node_cc1))
                else:
                    input_cc0.extend(itemgetter(
                        *(self.nodes[name].inputs.keys()))(self.node_cc0))
                    input_cc1.extend(itemgetter(
                        *(self.nodes[name].inputs.keys()))(self.node_cc1))

                if self.nodes[name].node_type == "and":
                    self.node_cc1[name] = sum(input_cc1) + 1
                    self.node_cc0[name] = min(input_cc0) + 1
                elif self.nodes[name].node_type == "or":
                    self.node_cc1[name] = min(input_cc1) + 1
                    self.node_cc0[name] = sum(input_cc0) + 1
                elif self.nodes[name].node_type == "nand":
                    self.node_cc1[name] = min(input_cc0) + 1
                    self.node_cc0[name] = sum(input_cc1) + 1
                elif self.nodes[name].node_type == "nor":
                    self.node_cc1[name] = sum(input_cc0) + 1
                    self.node_cc0[name] = min(input_cc1) + 1
                elif self.nodes[name].node_type == "xor":
                    if len(input_cc0) == 2:
                        self.node_cc1[name] = min(
                            input_cc0[0] + input_cc1[1], input_cc0[1] + input_cc1[0]) + 1
                        self.node_cc0[name] = min(
                            input_cc0[0] + input_cc0[1], input_cc1[1] + input_cc1[0]) + 1
                    else:
                        print("only 1 input for xor")
                elif self.nodes[name].node_type == "xnor":
                    if len(input_cc0) == 2:
                        self.node_cc1[name] = min(
                            input_cc0[0] + input_cc0[1], input_cc1[1] + input_cc1[0]) + 1
                        self.node_cc0[name] = min(
                            input_cc0[0] + input_cc1[1], input_cc0[1] + input_cc1[0]) + 1
                    else:
                        print("only 1 input for xnor")
                elif self.nodes[name].node_type == "not":
                    self.node_cc1[name] = input_cc0[0] + 1
                    self.node_cc0[name] = input_cc1[0] + 1
                elif self.nodes[name].node_type == "buff":
                    self.node_cc1[name] = input_cc1[0] + 1
                    self.node_cc0[name] = input_cc0[0] + 1
            else:
                self.node_cc1[name] = 1
                self.node_cc0[name] = 1

        # observability
        # print(self.node_cc1)
        for name in reversed(self.topology_order):
            ob = set()
            for output in self.nodes[name].outputs:
                if len(self.nodes[output].inputs.keys()) > 1:
                    if self.nodes[output].node_type == "and":
                        input_cc1 = []
                        input_cc1.extend(itemgetter(
                            *(self.nodes[output].inputs.keys()))(self.node_cc1))
                        ob.add(sum(input_cc1) -
                               self.node_cc1[name] + self.node_co[output] + 1)
                    elif self.nodes[output].node_type == "or":
                        input_cc0 = []
                        input_cc0.extend(itemgetter(
                            *(self.nodes[output].inputs.keys()))(self.node_cc0))
                        ob.add(sum(input_cc0) -
                               self.node_cc0[name] + self.node_co[output] + 1)
                    elif self.nodes[output].node_type == "nand":
                        input_cc1 = []
                        # print("input_keys:", self.nodes[output].inputs.keys())
                        input_cc1.extend(itemgetter(
                            *(self.nodes[output].inputs.keys()))(self.node_cc1))
                        ob.add(sum(input_cc1) -
                               self.node_cc1[name] + self.node_co[output] + 1)
                    elif self.nodes[output].node_type == "nor":
                        input_cc0 = []
                        input_cc0.extend(itemgetter(
                            *(self.nodes[output].inputs.keys()))(self.node_cc0))
                        ob.add(sum(input_cc0) -
                               self.node_cc0[name] + self.node_co[output] + 1)
                    elif self.nodes[output].node_type == "xnor":
                        ob.add(self.node_co[output] + 1)
                    elif self.nodes[output].node_type == "xor":
                        ob.add(self.node_co[output] + 1)

                elif len(self.nodes[output].inputs) == 1:
                    ob.add(self.node_co[output] + 1)
            if len(ob) != 0:
                self.node_co[name] = min(ob)

        # low observability nodes
        num = int(self.node_size * ob_threshold)
        if num == 0:
            num = 1
        ob_list = list(self.node_co.values())
        threshold_value = hq.nlargest(num, ob_list)[-1]

        for name in self.node_co:
            if self.node_co[name] >= threshold_value:
                self.low_ob_node.append(name)
                self.avg_co = self.avg_co + self.node_co[name]

        print("low_ob_node_size", len(self.low_ob_node))
        self.avg_co = float(self.avg_co / len(self.low_ob_node))

    def simulator_bench(self, input_patterns, new_topology_order=None):
        if new_topology_order is None:
            new_topology_order = {}
        new_topology_order.clear()
        for i, pi in enumerate(self.pis):
            new_topology_order[pi] = input_patterns[:, i]
        
        for node_name in self.topology_list:
            if node_name in new_topology_order:
                continue
            
            node = self.nodes[node_name]
            input_names = list(node.inputs)
            input_arrays = [new_topology_order[inp] for inp in input_names]
            
            if node.node_type == "and":
                result = np.all(np.stack(input_arrays, axis=0), axis=0)
            elif node.node_type == "or":
                result = np.any(np.stack(input_arrays, axis=0), axis=0)
            elif node.node_type == "nand":
                result = np.logical_not(np.all(np.stack(input_arrays, axis=0), axis=0))
            elif node.node_type == "nor":
                result = np.logical_not(np.any(np.stack(input_arrays, axis=0), axis=0))
            elif node.node_type == "xor":
                result = (np.sum(np.stack(input_arrays, axis=0), axis=0) % 2 == 1)
            elif node.node_type == "xnor":
                result = (np.sum(np.stack(input_arrays, axis=0), axis=0) % 2 == 0)
            elif node.node_type == "not":
                if len(input_arrays) != 1:
                    print(f"Warning: Not gate '{node_name}' 預期 1 個輸入，但實際有 {len(input_arrays)} 個")
                result = np.logical_not(input_arrays[0])
            elif node.node_type == "buff":
                if len(input_arrays) != 1:
                    print(f"Warning: Buff gate '{node_name}' 預期 1 個輸入，但實際有 {len(input_arrays)} 個")
                result = input_arrays[0]
            elif node.node_type == "pi":
                result = new_topology_order[node_name]
            else:
                print(f"Unknown gate type '{node.node_type}' in node '{node_name}'")
                result = np.zeros(len(input_patterns), dtype=bool)
            
            new_topology_order[node_name] = result
        
        for node_name, values in new_topology_order.items():
            self.topology_order[node_name] = values[-1]
        
        return new_topology_order

    def rare_wire(self, threshold, pattern_num):

        print("rare wire pattern num", pattern_num)
        # self.zero_size = dict.fromkeys(self.nodes, 0.0)
        # self.one_size = dict.fromkeys(self.nodes, 0.0)

        input_patterns = np.random.choice(
            [False, True], size=(pattern_num, self.pi_size))
        simulation_results = self.simulator_bench(input_patterns)
        for node_name, values in simulation_results.items():
            ones = int(np.sum(values))
            zeros = pattern_num - ones
            self.one_size[node_name] += ones
            self.zero_size[node_name] += zeros

        for name in self.nodes:
            self.zero_size[name] = self.zero_size[name] / pattern_num
            self.one_size[name] = self.one_size[name] / pattern_num

            if self.zero_size[name] <= threshold:
                self.rare_zero[name] = self.zero_size[name]
                self.avg_cc = self.avg_cc + self.node_cc0[name]

            elif self.one_size[name] <= threshold:
                self.rare_one[name] = self.one_size[name]
                self.avg_cc = self.avg_cc + self.node_cc1[name]

        if (len(self.rare_zero) + len(self.rare_one)) == 0:
            print("!!!!rare zero and one is 0!!!!\n") 
            self.avg_cc = 0   
        else:
            self.avg_cc = float(
                self.avg_cc / (len(self.rare_zero) + len(self.rare_one)))

        for name in self.rare_zero:
            self.backtrace(name, 0)
        for name in self.rare_one:
            self.backtrace(name, 1)

    def backtrace(self, name, value):

        if name in self.pis:
            return 0
        else:
            if value == 0:
                if self.nodes[name].node_type == "nand":
                    for input in self.nodes[name].inputs:
                        if input not in self.rare_partail_nodes_one:
                            self.rare_partail_nodes_one[input] = 1
                        else:
                            self.rare_partail_nodes_one[input] = self.rare_partail_nodes_one[input] + 1
                        self.backtrace(input, 1)

                elif self.nodes[name].node_type == "or":
                    for input in self.nodes[name].inputs:
                        if input not in self.rare_partail_nodes_zero:
                            self.rare_partail_nodes_zero[input] = 1
                        else:
                            self.rare_partail_nodes_zero[input] = self.rare_partail_nodes_zero[input] + 1
                        self.backtrace(input, 0)

                elif self.nodes[name].node_type == "not":
                    for input in self.nodes[name].inputs:
                        if input not in self.rare_partail_nodes_one:
                            self.rare_partail_nodes_one[input] = 1
                        else:
                            self.rare_partail_nodes_one[input] = self.rare_partail_nodes_one[input] + 1
                        self.backtrace(input, 1)
                elif self.nodes[name].node_type == "buff":
                    for input in self.nodes[name].inputs:
                        if input not in self.rare_partail_nodes_zero:
                            self.rare_partail_nodes_zero[input] = 1
                        else:
                            self.rare_partail_nodes_zero[input] = self.rare_partail_nodes_zero[input] + 1
                        self.backtrace(input, 0)
            else:
                if self.nodes[name].node_type == "and":
                    for input in self.nodes[name].inputs:
                        if input not in self.rare_partail_nodes_one:
                            self.rare_partail_nodes_one[input] = 1
                        else:
                            self.rare_partail_nodes_one[input] = self.rare_partail_nodes_one[input] + 1
                        self.backtrace(input, 1)

                elif self.nodes[name].node_type == "nor":
                    for input in self.nodes[name].inputs:
                        if input not in self.rare_partail_nodes_zero:
                            self.rare_partail_nodes_zero[input] = 1
                        else:
                            self.rare_partail_nodes_zero[input] = self.rare_partail_nodes_zero[input] + 1
                        self.backtrace(input, 0)

                elif self.nodes[name].node_type == "not":
                    for input in self.nodes[name].inputs:
                        if input not in self.rare_partail_nodes_zero:
                            self.rare_partail_nodes_zero[input] = 1
                        else:
                            self.rare_partail_nodes_zero[input] = self.rare_partail_nodes_zero[input] + 1
                        self.backtrace(input, 0)
                elif self.nodes[name].node_type == "buff":
                    for input in self.nodes[name].inputs:
                        if input not in self.rare_partail_nodes_one:
                            self.rare_partail_nodes_one[input] = 1
                        else:
                            self.rare_partail_nodes_one[input] = self.rare_partail_nodes_one[input] + 1
                        self.backtrace(input, 1)

    def partial_simulate(self, index, copy_result):

        depth = dict()
        max_depth = 0
        pq = queue.PriorityQueue()
        name = self.topology_list[index]
        for output in self.nodes[name].outputs:
            pq.put(self.nodes[output].topo_index)
            depth[output] = 0

        while not pq.empty():
            i = pq.get()
            name = self.topology_list[i]
            pre_value = copy_result[name]
            input_values = []

            if len(self.nodes[name].inputs) != 0:

                if len(self.nodes[name].inputs.keys()) == 1:
                    input_values.append(itemgetter(
                        *(self.nodes[name].inputs.keys()))(copy_result))
                else:
                    input_values.extend(itemgetter(
                        *(self.nodes[name].inputs.keys()))(copy_result))

                if self.nodes[name].node_type == "and":
                    copy_result[name] = all(input_values)
                elif self.nodes[name].node_type == "or":
                    copy_result[name] = any(input_values)
                elif self.nodes[name].node_type == "nand":
                    copy_result[name] = not all(input_values)
                elif self.nodes[name].node_type == "nor":
                    copy_result[name] = not any(input_values)
                elif self.nodes[name].node_type == "xor":
                    copy_result[name] = (sum(input_values) % 2 == 1)
                elif self.nodes[name].node_type == "xnor":
                    copy_result[name] = (sum(input_values) % 2 == 0)
                elif self.nodes[name].node_type == "not":
                    if len(self.nodes[name].inputs) != 1:
                        print(
                            "!!!in simulator not gate found data structure wrong!!!")
                        print(self.nodes[name].inputs)
                    copy_result[name] = not input_values[0]
                elif self.nodes[name].node_type == "buff":
                    if len(self.nodes[name].inputs) != 1:
                        print("!!!in simulator buff found data structure wrong!!!")
                    copy_result[name] = input_values[0]

            if pre_value != copy_result[name]:
                for output in self.nodes[name].outputs:
                    pq.put(self.nodes[output].topo_index)
                    depth[output] = depth[name] + 1
                max_depth = max(max_depth, depth[name] + 1)

        output_value = []
        if self.po_size == 1:
            output_value.append(itemgetter(*(self.pos.keys()))(copy_result))
        else:
            output_value.extend(itemgetter(*(self.pos.keys()))(copy_result))
        return output_value, max_depth

    def next_state(self, triggered_num, observed_num, input_pattern = None):

        # for pi in range(self.pi_size):
        #     if action[pi] == True:
        #         self.current_input_pattern[pi] = not self.current_input_pattern[pi]
                
        if input_pattern is not None:
            self.current_input_pattern = input_pattern
        result = self.simulator(self.current_input_pattern)

        # all value
        n_state = list(self.topology_order.values())

        # rare value
        partail_trigger_dict = dict()
        for name in self.rare_partail_nodes_zero:
            if self.topology_order[name] == False:
                partail_trigger_dict[name] = self.rare_partail_nodes_zero[name]

        for name in self.rare_partail_nodes_one:
            if self.topology_order[name] == True:
                partail_trigger_dict[name] = self.rare_partail_nodes_one[name]

        triggered_dict = dict()

        for name in self.rare_zero:
            if self.topology_order[name] == False:
                triggered_dict[name] = self.node_cc0[name]

        for name in self.rare_one:
            if self.topology_order[name] == True:
                triggered_dict[name] = self.node_cc1[name]

        for name in triggered_dict:
            triggered_num[name] = triggered_num[name] + 1

        # sensitive
        sensitive_dict = dict()
        for ob_name in self.low_ob_node:
            copy_circuit = self.topology_order.copy()
            index = self.nodes[ob_name].topo_index
            copy_circuit[ob_name] = not copy_circuit[ob_name]
            sen_result, max_depth = self.partial_simulate(index, copy_circuit)
            sensitive_dict[ob_name] = max_depth
            if result != sen_result:
                sensitive_dict[ob_name] += self.node_co[ob_name]
                observed_num[ob_name] = observed_num[ob_name] + 1

        n_state = list(triggered_num.values()) + \
            list(observed_num.values()) + n_state

        return n_state, triggered_dict, sensitive_dict, result,  partail_trigger_dict

    def low_ob_tfo(self):
        for name in self.low_ob_node:
            q = queue.Queue()
            self.payload_TFO[name] = dict()
            visited = set()  # keep track of visited nodes
            q.put(name)
            while not q.empty():
                node = q.get()
                if node not in visited:  # only process the node if it hasn't been visited
                    visited.add(node)  # mark the node as visited
                    for output in self.nodes[node].outputs:
                        if output in self.rare_node_name:
                            self.payload_TFO[name][output] = True
                        q.put(output)
