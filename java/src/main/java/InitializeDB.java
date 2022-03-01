import java.io.*;
import org.json.simple.*;
import org.json.simple.parser.*;
import java.sql.*;
import java.util.Iterator;

public class InitializeDB {
    // JDBC driver name and database URL
    static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
    static final String DB_URL = "jdbc:mysql://localhost/cve"; // cve is the database name!
    //  Database credentials
    static final String USER = "YOUR_USERNAME_HERE";
    static final String PASS = "YOUR_PASSWORD_HERE";

    public static void main(String[] args) throws SQLException {
        Connection conn = null;
        try {
            //STEP 2: Register JDBC driver
            Class.forName("com.mysql.jdbc.Driver");

            //STEP 3: Open a connection
            System.out.println("Connecting to database...");
            conn = DriverManager.getConnection(DB_URL, USER, PASS);

            //STEP 4: Store the JSON contents to MySQL table
            String[] files = {"nvdcve-1.1-2010.json", "nvdcve-1.1-2011.json", "nvdcve-1.1-2012.json", "nvdcve-1.1-2013.json", "nvdcve-1.1-2014.json", "nvdcve-1.1-2015.json", "nvdcve-1.1-2016.json", "nvdcve-1.1-2017.json", "nvdcve-1.1-2018.json", "nvdcve-1.1-2019.json", "nvdcve-1.1-2020.json", "nvdcve-1.1-2021.json", "nvdcve-1.1-recent.json", "nvdcve-1.1-modified.json"};
            int totalCVE = 0;
            for (String file : files) {
                System.out.println("Processing file" + file);
                totalCVE += processJson("PATH_TO_NVDCVE_JSON_DIR" + file, conn); // specify CVE JSON file here
            }
            System.out.println("Total number of CVE records: " + totalCVE);
        } catch (SQLException | ClassNotFoundException se) {
            //Handle errors for JDBC
            se.printStackTrace();
            conn.close();
        }
    }

    private static int processJson(String filePath, Connection conn) throws SQLException {
        JSONParser jsonParser = new JSONParser();
        try {
            JSONObject jsonObject = (JSONObject) jsonParser.parse(new FileReader(filePath));
            String count = (String) jsonObject.get("CVE_data_numberOfCVEs");
            int nrecords = Integer.parseInt(count);
            JSONArray arr = (JSONArray) jsonObject.get("CVE_Items");
            System.out.println("Total number of CVE entries: " + nrecords);

            Iterator<JSONObject> iterator = arr.iterator();
            while (iterator.hasNext()) {
                JSONObject curJSONObject = iterator.next();

                try {
                    // get current CVE ID
                    JSONObject curCVE = (JSONObject) curJSONObject.get("cve");
                    JSONObject curCVEMeta = (JSONObject) curCVE.get("CVE_data_meta");
                    String curCVEID = (String) curCVEMeta.get("ID");

                    // get current CVE's impact score and exploitability score
                    JSONObject curImpact = (JSONObject) curJSONObject.get("impact");

                    JSONObject curCVSS = (JSONObject) curImpact.get("baseMetricV3");
                    if (curCVSS == null) {
                        curCVSS = (JSONObject) curImpact.get("baseMetricV2");
                    }

                    if (curCVSS == null) // This indicates the CVE is rejected, e.g., CVE-2019-0034
                        continue;

                    double curImpactScore = (double) curCVSS.get("impactScore");
                    double curExploitScore = (double) curCVSS.get("exploitabilityScore");

                    // get CVE description
                    JSONObject curDesc = (JSONObject) curCVE.get("description");
                    JSONArray curDescArr = (JSONArray) curDesc.get("description_data");
                    JSONObject curDescObj = (JSONObject) curDescArr.get(0);
                    String curDescStr = (String) curDescObj.get("value");

                    // store the current CVE ID, impactScore, exploitabilityScore, and description to MySQL database
                    PreparedStatement pstmt = conn.prepareStatement("REPLACE INTO cvetabupdate values (?, ?, ?, ?)"); // specify MySQL table here
                    pstmt.setString(1, curCVEID);
                    pstmt.setDouble(2, curExploitScore);
                    pstmt.setDouble(3, curImpactScore);

                    if (curDescStr != null)
                        pstmt.setString(4, curDescStr);
                    else
                        pstmt.setString(4, "");

                    pstmt.execute(); // do the actual writing to the table specified
                }

                catch (Exception e) {
                    continue;
                }
            }
            return nrecords;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return -1;
    }
}

