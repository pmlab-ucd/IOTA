import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.text.DecimalFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Graph {
    class Node {
        int id;
        String des;
        String type;
        double prob;
        double impact;
        String subType;
        int depth;

        public Node(int id, String des, String type, double prob, String subType) {
            this.id = id;
            this.des = des;
            this.type = type;
            this.prob = prob;
            this.subType = subType;
        }
    }

    int nNodes;
    int nEdges;
    Map<Integer, Node> nodes; // nodeID --> actual node
    Map<Integer, List<Integer>> edges; // nodeID --> list of adjacent nodes
    Map<Integer, List<Integer>> preds; // nodeID --> list of its predecessors

    public Graph(File nodesFile, File edgesFile, File metricFile) throws FileNotFoundException { // construct a graph from two csv files
        nodes = new HashMap<>();
        edges = new HashMap<>();
        preds = new HashMap<>();
        Scanner scanner;
        /* first read nodesFile */
        scanner = new Scanner(nodesFile);
        while (scanner.hasNextLine()) {
            nNodes++;
            processNodeLine(nodes, scanner.nextLine());
        }

        /* then read edgesFile */
        scanner = new Scanner(edgesFile);
        while (scanner.hasNextLine()) {
            processEdgeLine(edges, preds, scanner.nextLine());
        }

        /* next, fix the initial probability and impact for each CVE */
        // read in the cvemetric.csv file and build the dictionary for CVEID and metrics
        scanner = new Scanner(metricFile);
        Map<String, double[]> metric = new HashMap<>(); // CVEID --> [probability, impact]
        while (scanner.hasNextLine()) {
            processCVELine(metric, scanner.nextLine());
        }

        // fix the metrics for the nodes of the graph
        fixMetric(nodes, edges, metric);
    }

    private void processNodeLine(Map<Integer, Node> nodes, String nodeLine) {
        Scanner rowScanner = new Scanner(nodeLine);
        String line = rowScanner.nextLine();
        String[] strArray = line.split(",(?=([^\"]*\"[^\"]*\")*[^\"]*$)");
        int id = Integer.parseInt(strArray[0]);
        String des = strArray[1].replaceAll("\"", "");
        String type = strArray[2].replaceAll("\"", "");
        double prob = Double.parseDouble(strArray[3]);

        String subType = "";
        if (type.equals("AND")) {
            if (des.startsWith("Exploit"))
                subType = "Exploit";
            else if (des.startsWith("Execution"))
                subType = "Execution";
        }
        if (id == 1) {
            subType = "Goal";
        }

        nodes.put(id, new Node(id, des, type, prob, subType));
    }

    private void processEdgeLine(Map<Integer, List<Integer>> edges, Map<Integer, List<Integer>> preds, String edgeLine) {
        Scanner rowScanner = new Scanner(edgeLine);
        rowScanner.useDelimiter(",");

        int to = rowScanner.nextInt();
        int from = rowScanner.nextInt();

        if (!edges.containsKey(from))
            edges.put(from, new ArrayList<>());
        if (!edges.get(from).contains(to)) {
            nEdges++;
            edges.get(from).add(to);
        }

        if (!preds.containsKey(to))
            preds.put(to, new ArrayList<>());
        if (!preds.get(to).contains(from)) {
            preds.get(to).add(from);
        }
    }

    private void processCVELine(Map<String, double[]> metric, String metricLine) {
        Scanner rowScanner = new Scanner(metricLine);
        rowScanner.useDelimiter(",");

        String cveid = rowScanner.next();
        double prob = rowScanner.nextDouble();
        double impact = rowScanner.nextDouble();
        metric.put(cveid, new double[] {prob, impact});
    }

    private void fixMetric(Map<Integer, Node> nodes, Map<Integer, List<Integer>> edges, Map<String, double[]> metric) {
        for (int node : nodes.keySet()) {
            String curDes = nodes.get(node).des;
            if (curDes.contains("CVE-")) {
                String curCve = curDes.substring(curDes.indexOf("CVE"), curDes.indexOf('\'', curDes.indexOf('\'') + 1));
                List<Integer> nextNodes = edges.get(node);
                // now let's fix the probability
                for (int nextNode : nextNodes) {
                    nodes.get(nextNode).prob = metric.get(curCve)[0];
                    nodes.get(nextNode).impact = metric.get(curCve)[1];
                }
            }
        }
    }

    /*
     * Assumption: the input graph has no cycles
     * Pseudocode: For an unprocessed node, if all of its predecessors are processed, then update its probability,
     * and add it to the processed set.
     * */
    private void calProb() {
        Set<Integer> processed = new HashSet<>();
        Queue<Integer> unprocessed = new LinkedList<>();

        for (int node : nodes.keySet()) {
            if (nodes.get(node).type.equals("LEAF")) {
                processed.add(node);
            }
            else {
                unprocessed.add(node);
            }
        }

        while (processed.size() < nNodes) {
            int node = unprocessed.poll();
            boolean found = true;
//            System.out.println(node);  // uncomment for debugging purposes
            for (int pred : preds.get(node)) {
                if (!processed.contains(pred)) {
                    found = false;
                    unprocessed.add(node);
                    break;
                }
            }
            if (!found)
                continue;

            if (nodes.get(node).type.equals("AND")) {
                for (int pred : preds.get(node))
                    nodes.get(node).prob *= nodes.get(pred).prob;
            }
            else if (nodes.get(node).type.equals("OR")) {
                double val = nodes.get(preds.get(node).get(0)).prob;
                for (int i = 1; i < preds.get(node).size(); i++)
                    val = val + nodes.get(preds.get(node).get(i)).prob - val * nodes.get(preds.get(node).get(i)).prob;
                nodes.get(node).prob = val;
            }

            processed.add(node);
        }
    }
    /*
        // The leaf node has depth 0, so by depth I mean the maximum number of layers - 1
        private int calDepth() {
            int node;
            for (node = 1; node <= nodes.size(); node++) {
                if (nodes.get(node).subType.equals("Goal"))
                    break;
            }
            return computeDepth(node);
        }

        private int computeDepth(int node) {
            if (nodes.get(node).type.equals("LEAF"))
                return 0;

            List<Integer> temp = preds.get(node);
            int res = computeDepth(temp.get(0));
            for (int i = 0; i < temp.size(); i++)
                res = Math.max(res, computeDepth(temp.get(i)));
            return res+1;
        }

        private int compute_steps_from_attack_initial_node_to_goal_node() {
            int nodeAttackerInitialAccess = -1;
            int nodeAttackerProximity = -1;
            int nodeGoal = -1;
            for (int node = 1; node <= nodes.size(); node++) {
                if (nodes.get(node).des.contains("attackerInitialAccess"))
                    nodeAttackerInitialAccess = node;
                if (nodes.get(node).des.contains("attackerProximity"))
                    nodeAttackerProximity = node;
                if (nodes.get(node).subType.equals("Goal"))
                    nodeGoal = node;
            }

            int stepsAttackerInitialAccess = -1;
            int stepsAttackerProximity = -1;

            if (nodeAttackerInitialAccess > 0)
                stepsAttackerInitialAccess = compute_steps_from_given_node_to_goal_node(nodeAttackerInitialAccess, nodeGoal);

            if (nodeAttackerProximity > 0)
                stepsAttackerProximity = compute_steps_from_given_node_to_goal_node(nodeAttackerProximity, nodeGoal);

            return Math.max(stepsAttackerInitialAccess, stepsAttackerProximity);
        }

        private int compute_steps_from_given_node_to_goal_node(int given_node, int goal_node) {
            // mark the depth using BFS
            int curDepth = 0;
            List<Integer> queue = new ArrayList<>();
            queue.add(given_node);
            int curQueueLength = queue.size();
            while (nodes.get(goal_node).depth == 0) {
                for (int i = 0; i < curQueueLength; i++) {
                    int curNode = queue.remove(0);
                    nodes.get(curNode).depth = curDepth;

                    if (edges.containsKey(curNode))
                        for (int child : edges.get(curNode))
                            queue.add(child);
                }
                curDepth++;
                curQueueLength = queue.size();
            }

            return nodes.get(goal_node).depth / 2;
        }
    */
    /* Generate the final VERTICES.CSV file to replace the original one
     * 1. Each vertex has final computed probability
     * 2. Goal is also highlighted
     * */
    private void generateCSV(String path) throws IOException {
        FileWriter csvWriter = new FileWriter(path + "VERTICES_final.CSV");
        for (int node = 1; node <= nodes.size(); node++) {
            Node curNode = nodes.get(node);
            csvWriter.append(String.valueOf(node) + ","); // write node id
            if (curNode.subType.equals("Goal")) // write description
                csvWriter.append("\"GOAL (" + curNode.des + ")\"" + ",");
            else
                csvWriter.append("\"" + curNode.des + "\",");

            csvWriter.append("\"" + curNode.type + "\","); // write AND, OR, LEAF
            csvWriter.append(String.valueOf(Math.round(curNode.prob * 10000) / 10000.0)); // write probability
            csvWriter.append("\n");
        }
        csvWriter.close();

        // delete the original file and rename the new file
        File file = new File(path + "VERTICES.CSV");
        file.delete();
        File f1 = new File(path + "VERTICES_final.CSV");
        File f2 = new File(path + "VERTICES.CSV");
        f1.renameTo(f2);
    }

    /*** Below are methods used to generate statistics for paper evaluation ***/
    /* For an attack graph, get the probability of attack goal node */
    private static String getGoalProb(Graph graph) {
        DecimalFormat df2 = new DecimalFormat("#.##");

        for (int node : graph.nodes.keySet()) {
            if (graph.nodes.get(node).subType.equals("Goal"))
                return df2.format(graph.nodes.get(node).prob);
        }
        return null;
    }

    /* For an attack graph, count the CVE-ID occurrences and return a map */
    private static Map<String, Integer> getCVECount(Graph graph) {
        Map<String, Integer> cveCount = new HashMap<>();

        // pattern for CVE ID
        Pattern pattern = Pattern.compile("CVE-\\d{4}-\\d{4,7}");

        String cveID;
        for (int node : graph.nodes.keySet()) {
            Node curNode = graph.nodes.get(node);
            if (curNode.type.equals("LEAF") && curNode.des.startsWith("vulExists(")) {
                // Search the CVE ID pattern in the node description
                Matcher m = pattern.matcher(curNode.des);
                while (m.find()) {
                    cveID = m.group();

                    if (!cveCount.containsKey(cveID)) cveCount.put(cveID, 0);
                    cveCount.put(cveID, cveCount.get(cveID)+1);
                }
            }
        }
        return cveCount;
    }

    /* For an attack graph, count the IoT app occurrences and return a map */
    private static Map<String, Integer> getAppCount(Graph graph) {
        Map<String, Integer> appCount = new HashMap<>();

        // pattern for App ID
        Pattern pattern = Pattern.compile("App [0-9]+");

        String appID;
        for (int node : graph.nodes.keySet()) {
            Node curNode = graph.nodes.get(node);
            if (curNode.type.equals("AND") && curNode.des.startsWith("RULE")) {
                // Search the App ID pattern in the node description
                Matcher m = pattern.matcher(curNode.des);
                while (m.find()) {
                    appID = m.group(0);

                    if (!appCount.containsKey(appID)) appCount.put(appID, 0);
                    appCount.put(appID, appCount.get(appID)+1);
                }
            }
        }
        return appCount;
    }

    /* For an attack graph, count the indirect dependency occurrences and return a map */
    private static Map<String, Integer> getInirectDependencyCount(Graph graph) {
        Map<String, Integer> indirectDependencyCount = new HashMap<>();
        indirectDependencyCount.put("temperature", 0);
        indirectDependencyCount.put("humidity", 0);
        indirectDependencyCount.put("smoke", 0);
        indirectDependencyCount.put("voice", 0);
        indirectDependencyCount.put("illuminance", 0);
        indirectDependencyCount.put("water", 0);

        for (int node : graph.nodes.keySet()) {
            Node curNode = graph.nodes.get(node);
            if (curNode.type.equals("OR") && (curNode.des.startsWith("high(temperature)") || curNode.des.startsWith("low(temperature)")))
                indirectDependencyCount.put("temperature", indirectDependencyCount.get("temperature")+1);
            if (curNode.type.equals("OR") && (curNode.des.startsWith("high(humidity)") || curNode.des.startsWith("low(humidity)")))
                indirectDependencyCount.put("humidity", indirectDependencyCount.get("humidity")+1);
            if (curNode.type.equals("OR") && curNode.des.startsWith("exists(smoke)"))
                indirectDependencyCount.put("smoke", indirectDependencyCount.get("smoke")+1);
            if (curNode.type.equals("OR") && curNode.des.startsWith("voice("))
                indirectDependencyCount.put("voice", indirectDependencyCount.get("voice")+1);
            if (curNode.type.equals("OR") && (curNode.des.startsWith("high(illuminance)") || curNode.des.startsWith("low(illuminance)")))
                indirectDependencyCount.put("illuminance", indirectDependencyCount.get("illuminance")+1);
            if (curNode.type.equals("OR") && curNode.des.startsWith("exists(waterLeakage)"))
                indirectDependencyCount.put("water", indirectDependencyCount.get("water")+1);
        }

        return indirectDependencyCount;
    }

    /* Print the statistics for each generated attack graph */
    public static void printMap(Map<String, Integer> map) {
        String res = "";
        for (String key : map.keySet()) {
            res += key + ": " + map.get(key) + ", ";
        }
        if (res.length() == 0)
            System.out.println("");
        else
            System.out.println(res.substring(0, res.length() - 2));
    }

    public static void main(String[] args) throws IOException {
        String path = args[0]; // here we should specify the path to the VETICES.CSV and ARCS.CSV files

        File nodesFile = new File(path + "VERTICES.CSV");
        File edgesFile = new File(path + "ARCS.CSV");
        File metricFile = new File(path + "cvemetric.csv");

        Graph graph = new Graph(nodesFile, edgesFile, metricFile);

        graph.calProb();

        graph.generateCSV(path);

        assert graph.nNodes == graph.nodes.size();
        assert graph.nEdges == graph.edges.size();

        System.out.println(graph.nNodes + "," + graph.nEdges);

        printMap(getCVECount(graph));
        printMap(getAppCount(graph));
        printMap(getInirectDependencyCount(graph));
    }

    // Below is the test main class!
    /*
    public static void main(String[] args) throws IOException {
        String path = args[0]; // here we should specify the path to the VETICES.CSV and ARCS.CSV files

        File nodesFile = new File(path + "VERTICES.CSV");
        File edgesFile = new File(path + "ARCS.CSV");
        File metricFile = new File(path + "cvemetric.csv");

        Graph graph = new Graph(nodesFile, edgesFile, metricFile);

        graph.calProb();

        graph.generateCSV(path);

        assert graph.nNodes == graph.nodes.size();
        assert graph.nEdges == graph.edges.size();

        System.out.println(graph.nNodes + "," + graph.nEdges);

        printMap(getCVECount(graph));
        printMap(getAppCount(graph));
        printMap(getInirectDependencyCount(graph));
    }
    */
}
