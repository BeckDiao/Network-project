# Network-project
1.	Objectives
-	Understand different load balancing (LB) algorithms
-	Implement LB algorithms using OpenFlow Controller and Mininet Emulation
-	Enforce LB algorithm on real testbed
2.	Lab Tutorial
2.1	Environment Setup: Fat Tree Network Topology and Traffic Matrix
Fat Tree is one of the typical topologies of modern data center. A 16-host Fat tree topology is denoted as in Figure 1. 

Figure 1. Fat Tree Topology

2.2	Tasks: 
1)	Create a smaller use-case


Use-case codes for the first task is attached in file “use_case_10.py”.

2)	Implement the controller script with load-balancing algorithms  to control the flows, and conduct measurements based on it. 

Use-case codes for the first task is attached in file “use_case_10.py”.
Code for Left Path Routing (LPR) is attached in file “LPR_final.py”.
Code for Random Selection Routing (RSR) is attached in file “Random.py”.

In each script, students shall periodically pull the counters of the flow entries to measure the loads for links. The sampling time for each pulling shall be 10 seconds.

	For Question 1, the monitor code for LPR is attached in file “Monitor1_1.py”, the code for RSR is attached in file “Monitor1_2.py” to analysis the link load for all links at each sampling time.
	For Question 2, the monitor code for LPR is attached in file “Monitor2.py”.
	All the captured data for the following questions is shown in attached Excel file “Data.xlsx”.


1.  Each student shall plot the results for the all the links, which records the maximum link load, average link load, and minimum link load at each sampling time as denoted below. 





2. Each student shall measure the link load at each sampling time for one left path links.
	Using the NYU ID N10114552, the result is 0-8, for the topology in this lab, it is link between Host 1 and Host 9. According to left path routing, the path is shown in topo figure above:
	H1-eth1 -> S1-eth1 ->S1-eth3 -> S9-eth1 -> S9-eth3 -> S17-eth1 -> 
S17-eth4 -> S14-eth3 -> S14-eth1 -> S5-eth4 -> S5-eth1 ->H9-eth1





3. Please collect and plot the ping latency for each host to the neighboring hosts using plot.py as after running the parallel_traffic_generator.py or sequential_traffic_generator.py program.

