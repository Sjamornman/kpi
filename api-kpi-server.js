const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const os = require("os");

const app = express();
const port = process.env.PORT || 5008;

app.use(function (req, res, next) {
  const allowedOrigins = [
    "https://it.nkh.go.th",
    "http://192.168.99.70",
    "http://192.168.99.75",
  ];
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }

  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  ); // Include OPTIONS for preflight requests
  res.setHeader("Access-Control-Allow-Credentials", true);

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    return res.sendStatus(204); // No Content
  }

  next();
});

const SECRET_KEY = "xyz123abc987";

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use((req, res, next) => {
  //console.log(`Request received: ${req.method} ${req.url} from ${req.ip}`);
  next();
});

// MySQL connection pool
const local = mysql.createPool({
  connectionLimit: 10,
  host: "54.169.53.106",
  user: "kpi",
  password: "Kpi@10706",
  database: "kpi",
});

const localPool = local.promise();

function hashPassword(password) {
  // First, create a SHA-1 hash of the password
  const sha1Hash = crypto.createHash("sha1").update(password).digest("hex");

  // Then, create an MD5 hash of the SHA-1 hash
  const md5Hash = crypto.createHash("md5").update(sha1Hash).digest("hex");

  return md5Hash; // Return the final MD5 hash
}

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log(username);
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required." });
  }

  try {
    const hashedPassword = hashPassword(password);
    const [user] = await localPool.query(
      `SELECT td.dep_code, td.dep_name_short, td.dep_name_th FROM tb_user tu left join tb_department td on tu.user_name = td.dep_name_short WHERE tu.user_name = '${username}' and tu.user_password = '${hashedPassword}'`
    );

    if (user.length === 0) {
      const token = jwt.sign({
        authenticated: false,
        redirectUrl: "/kpi/login.html",
        user_dep_code: user[0].dep_code,
        user_dep_name: user[0].dep_name_th,
      });
      res.json({ token, redirectUrl: "/kpi/login.html" });
    } else {
      const token = jwt.sign(
        {
          authenticated: true,
          redirectUrl: "/kpi",
          user_dep_code: user[0].dep_code,
          user_dep_name: user[0].dep_name_th,
        },
        "your-secret-key",
        { expiresIn: "1h" }
      );
      res.json({ token, redirectUrl: "/kpi" });
    }
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Session check endpoint
app.get("/check-session", (req, res) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.json({ authenticated: false, redirectUrl: "/kpi/login.html" });
  }

  jwt.verify(token, "your-secret-key", (err, decoded) => {
    if (err) {
      return res.json({ authenticated: false, redirectUrl: "/kpi/login.html" });
    }

    return res.json({
      authenticated: true,
      redirectUrl: decoded.redirectUrl,
      user_dep_code: decoded.user_dep_code,
      user_dep_name: decoded.user_dep_name,
    });
  });
});

app.post("/logout", (req, res) => {
  const token = jwt.sign(
    {
      authenticated: false,
      redirectUrl: "/kpi/login.html",
      user_dep_code: null,
      user_dep_name: null,
    },
    SECRET_KEY,
    { expiresIn: "1h" }
  );
  return res.json({
    token,
    redirectUrl: "/kpi/login.html",
  });
});

app.get("/kpi/:user_dep/:score_date", async (req, res) => {
  const user_dep = req.params.user_dep;
  const score_date = req.params.score_date;

  try {
    const [result] = await localPool.query(
      `SELECT tt.kpi_code, tt.temp_code,tt.temp_name, tt.temp_type_a, temp_type_b, ts.temp_score_a , ts.temp_score_b, td.temp_a_detail, td.temp_b_detail, tt.temp_formula
      FROM tb_kpi_template tt
      LEFT OUTER JOIN tb_kpi_template_detail td on tt.temp_code = td.temp_code
      LEFT JOIN tb_score ts on tt.temp_code = ts.temp_code and ( ts.user_dep = '${user_dep}') and ts.score_date = '${score_date}' 
      WHERE  
      FIND_IN_SET('${user_dep}', tt.temp_type_a) > 0 OR 
      FIND_IN_SET('${user_dep}', tt.temp_type_b) > 0
      ORDER BY tt.kpi_code, tt.temp_code,tt.temp_name
      /*(${user_dep} in (tt.temp_type_a) or ${user_dep} in (tt.temp_type_b))*/  `
    );
    res.json(result);
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/kpicount/:user_dep/:score_date", async (req, res) => {
  const user_dep = req.params.user_dep;
  const score_date = req.params.score_date;

  try {
    const [result] = await localPool.query(
      `SELECT 
        COUNT(IF(FIND_IN_SET('${user_dep}', a.temp_type_a) > 0 and a.temp_score_a is null, 1, NULL)) AS count_a,
        COUNT(IF(FIND_IN_SET('${user_dep}', a.temp_type_b) > 0 and a.temp_score_b is null, 1, NULL)) AS count_b
        FROM
        (
            SELECT 
                tt.kpi_code, 
                tt.temp_code,
                tt.temp_name, 
                tt.temp_type_a, 
                tt.temp_type_b, 
                ts.temp_score_a, 
                ts.temp_score_b 
            FROM 
                tb_kpi_template tt
            LEFT JOIN 
                tb_score ts ON tt.temp_code = ts.temp_code 
                AND ts.user_dep = '${user_dep}' 
                AND ts.score_date = '${score_date}' 
            WHERE 
                (tt.temp_type_a LIKE '%${user_dep}%' OR tt.temp_type_b LIKE '%${user_dep}%')
        ) AS a`
    );
    res.json(result);
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/formular/:score_date", async (req, res) => {
  const score_date = req.params.score_date;
  try {
    const [result] = await localPool.query(
      `SELECT 
          tt.kpi_code, 
          tt.temp_code,
          tt.temp_name, 
          tt.temp_formula, 
          GROUP_CONCAT(DISTINCT CASE WHEN FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_a, ' ', '')) > 0 THEN tu.user_name END) AS temp_type_a,
          GROUP_CONCAT(DISTINCT CASE WHEN FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_b, ' ', '')) > 0 THEN tu.user_name END) AS temp_type_b,
          SUM(ts.temp_score_a) AS temp_score_a, 
          SUM(ts.temp_score_b) AS temp_score_b,
          GROUP_CONCAT(DISTINCT CASE WHEN tu.user_name IS NOT NULL AND ts.temp_score_a IS NOT NULL AND FIND_IN_SET(tu.user_dep_code, REPLACE(ts.user_dep, ' ', '')) > 0 THEN tu.user_name END) AS concatenated_score_a,
          GROUP_CONCAT(DISTINCT CASE WHEN tu.user_name IS NOT NULL AND ts.temp_score_b IS NOT NULL AND FIND_IN_SET(tu.user_dep_code, REPLACE(ts.user_dep, ' ', '')) > 0 THEN tu.user_name END) AS concatenated_score_b
      FROM 
          tb_kpi_template tt
      LEFT JOIN 
          tb_score ts ON tt.temp_code = ts.temp_code AND ts.score_date = '${score_date}' 
      LEFT JOIN 
          tb_user tu ON FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_a, ' ', '')) > 0 
                      OR FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_b, ' ', '')) > 0
      
      GROUP BY 
          tt.kpi_code, 
          tt.temp_code, 
          tt.temp_name, 
          tt.temp_formula, 
          tt.temp_type_a, 
          tt.temp_type_b;
      `
    );

    res.json(result);
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/runchart/:start/:end/:kpi_code", async (req, res) => {
  let start_month = req.params.start;
  let end_month = req.params.end;
  const kpi_code = req.params.kpi_code;

  start_month = `${start_month}-01`;
  end_month = `${end_month}-01`;

  console.log(start_month, end_month, kpi_code);

  try {
    const [result] = await localPool.query(
      `
        SELECT tr.kpi_code, tr.temp_code, tkt.temp_name, tr.score_date, GROUP_CONCAT(tr.evaluated_score) as rc_score 
        FROM tb_runchart tr
        LEFT OUTER JOIN tb_kpi_template tkt on tr.temp_code = tkt.temp_code
        WHERE tr.score_date BETWEEN '${start_month}' AND '${end_month}' AND tr.temp_code = '${kpi_code}' 
        GROUP BY kpi_code, temp_code, score_date
      `
    );

    // Check if result is not empty
    if (result.length > 0) {
      const formattedResult = result.map((item) => ({
        ...item,
        rc_score: item.rc_score ? item.rc_score.split(",").map(Number) : [], // Convert to an array of numbers, or empty array if null
      }));

      res.json(formattedResult);
    } else {
      // Return an empty array if no data is found
      res.json([]);
    }
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/kpi-code", async (req, res) => {
  try {
    const [result] = await localPool.query(
      `SELECT temp_code, temp_name FROM tb_kpi_template GROUP BY temp_code ORDER BY temp_code asc
      `
    );

    res.json(result);

    // Check if result is not empty
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/runchart-syndata", async (req, res) => {
  try {
    await tb_runchart_update(); // Call the tb_runchart_update function
    res.json({ message: "Task executed successfully." });
  } catch (error) {
    console.error("Error in /runchart route:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

const tb_runchart_update = async () => {
  try {
    const [results] = await localPool.query(
      `
       SELECT a.kpi_code, a.temp_code, a.temp_formula, a.score_date, a.temp_score_a, a.temp_score_b,
if(
	if(b.temp_type_a is null, 0 , b.temp_type_a) = if(a.concatenated_score_a is null, 0 , a.concatenated_score_a) 
	and if(b.temp_type_b is null, 0 , b.temp_type_b) = if(a.concatenated_score_b is null, 0 , a.concatenated_score_b), 1, 0
) as check_status FROM
      (
      SELECT 
        tt.kpi_code, 
        tt.temp_code,
        tt.temp_name, 
        tt.temp_formula, 
        DATE_FORMAT(ts.score_date, '%Y-%m-%d') AS score_date,
        SUM(ts.temp_score_a) AS temp_score_a, 
        SUM(ts.temp_score_b) AS temp_score_b,
        GROUP_CONCAT(if(ts.temp_score_a is not null and ts.temp_score_a <> '', tu.user_name, null) ORDER BY tu.user_name) as concatenated_score_a,
        GROUP_CONCAT(if(ts.temp_score_b is not null and ts.temp_score_b <> '', tu.user_name, null) ORDER BY tu.user_name) as concatenated_score_b
      FROM 
          tb_kpi_template tt
      LEFT JOIN tb_user tu ON (FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_a, ' ', '')) > 0 
                      OR FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_b, ' ', '')) > 0 )
      LEFT JOIN tb_score ts ON tt.temp_code = ts.temp_code  AND tu.user_dep_code = ts.user_dep
      /*WHERE tt.temp_code = 'MMSO005' and ts.score_date = '2024-10-01' */
      GROUP BY 
          tt.kpi_code, 
          tt.temp_code, 
          tt.temp_name, 
          tt.temp_formula, 
          tt.temp_type_a, 
          tt.temp_type_b,
          ts.score_date
      ) as a

      LEFT OUTER JOIN 
      (
        SELECT 
        tt.kpi_code, 
        tt.temp_code,
        GROUP_CONCAT(DISTINCT CASE WHEN FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_a, ' ', '')) > 0 THEN tu.user_name END ORDER BY tu.user_name) AS temp_type_a,
        GROUP_CONCAT(DISTINCT CASE WHEN FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_b, ' ', '')) > 0 THEN tu.user_name END ORDER BY tu.user_name) AS temp_type_b
      FROM tb_kpi_template tt
      LEFT JOIN tb_user tu ON FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_a, ' ', '')) > 0 
                    OR FIND_IN_SET(tu.user_dep_code, REPLACE(tt.temp_type_b, ' ', '')) > 0
      GROUP BY 
        tt.kpi_code, 
        tt.temp_code, 
        tt.temp_type_a, 
        tt.temp_type_b
      ) as b 
      on a.temp_code = b.temp_code
      `
    );

    const updates = [];

    // Collect updates based on results
    for (const result of results) {
      if (result.check_status === 1) {
        const scoreA = result.temp_score_a;
        const scoreB = result.temp_score_b;
        const formula = result.temp_formula;

        result.evaluated_score = safeEval(formula, scoreA, scoreB);

        // Prepare to insert new records
        updates.push({
          kpi_code: result.kpi_code,
          temp_code: result.temp_code,
          evaluated_score: result.evaluated_score,
          score_date: result.score_date,
          action: "insert", // Indicate an insert action
        });
      } else if (result.check_status === 0) {
        // Prepare to set evaluated_score to null
        updates.push({
          kpi_code: result.kpi_code,
          temp_code: result.temp_code,
          evaluated_score: null, // Set to null to indicate removal
          score_date: result.score_date,
          action: "delete", // Indicate an update action
        });
      }
    }

    const placeholders = updates.map(() => "(?, ?, ?)").join(",");
    const query = `SELECT * FROM tb_runchart WHERE (kpi_code, temp_code, score_date) IN (${placeholders})`;
    const params = updates.flatMap((update) => [
      update.kpi_code,
      update.temp_code,
      update.score_date,
    ]);

    const existingRecords = await localPool.query(query, params);

    const existingMap = new Map();
    existingRecords[0].forEach((record) => {
      const key = `${record.kpi_code}-${record.temp_code}-${record.score_date}`;
      existingMap.set(key, record);

      // Get the current time in Bangkok
      const bangkokTime = new Intl.DateTimeFormat("en-US", {
        timeZone: "Asia/Bangkok",
        dateStyle: "short",
        timeStyle: "long",
      }).format(new Date());
    });

    // Validate updates and prepare queries
    const updateQueries = [];
    for (const update of updates) {
      const key = `${update.kpi_code}-${update.temp_code}-${update.score_date}`;
      if (update.action === "insert" && !existingMap.has(key)) {
        //console.log(update);
        updateQueries.push(
          localPool.query(
            `INSERT INTO tb_runchart (kpi_code, temp_code, evaluated_score, score_date) VALUES (?, ?, ?, ?)`,
            [
              update.kpi_code,
              update.temp_code,
              update.evaluated_score,
              update.score_date,
            ]
          )
        );
      } else if (update.action === "insert" && existingMap.has(key)) {
        console.log(update);
        updateQueries.push(
          localPool.query(
            `UPDATE tb_runchart SET evaluated_score = ? WHERE kpi_code = ? AND temp_code = ? AND score_date = ?`,
            [
              update.evaluated_score,
              update.kpi_code,
              update.temp_code,
              update.score_date,
            ]
          )
        );
      } else if (update.action === "delete" && existingMap.has(key)) {
        updateQueries.push(
          localPool.query(
            `DELETE FROM tb_runchart WHERE kpi_code = ? AND temp_code = ? AND score_date = ?`,
            [update.kpi_code, update.temp_code, update.score_date]
          )
        );
      }
    }

    // Execute all queries in parallel
    await Promise.all(updateQueries);

    console.log("Data processed and updated successfully.");
  } catch (error) {
    console.error("Error processing data:", error);
  }
};

tb_runchart_update();
// Run the task every hour
//setInterval(tb_runchart_update, 10000); // 3600000 ms = 1 hour

function safeEval(temp_formula, temp_score_a, temp_score_b) {
  if (temp_score_a !== 0 && temp_score_b !== 0) {
    // Replace with actual values
    const A = temp_score_a;
    const B = temp_score_b;
    const modifiedFormula = temp_formula
      .replace(/A/g, A)
      .replace(/B/g, B)
      .replace(/x/g, "*")
      .replace(/X/g, "*");

    try {
      const result = new Function("return " + modifiedFormula)();
      return isNaN(result) ? "Error" : result.toFixed(2);
    } catch (error) {
      console.error("Error evaluating formula:", error);
      return NaN; // Return NaN if there's an error
    }
  } else {
    return NaN;
  }
}

app.get("/get-user", async (req, res) => {
  try {
    const [result] = await localPool.query(
      `SELECT *

        FROM tb_department
        `
    );
    res.json(result);
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/submit", async (req, res) => {
  const data = req.body;
  console.log("Received form data:", data);

  const curdate = new Date().toISOString().split("T")[0];
  const baseScore = curdate.replace(/-/g, "");
  console.log(baseScore);
  const scoreNumber = await getNextScoreNumber(baseScore);

  try {
    const insertedRecords = [];

    for (const item of data) {
      const { score_date, kpi_code, temp_code, score_a, score_b, user_dep } =
        item;

      const [existingRecord] = await localPool.query(
        "SELECT * FROM tb_score WHERE kpi_code = ? AND temp_code = ? AND score_date = ? AND user_dep = ?",
        [kpi_code, temp_code, score_date, user_dep]
      );

      if (existingRecord.length === 0) {
        if (score_a === "" && score_b !== "") {
          await localPool.query(
            `INSERT INTO tb_score (score_date, score_number, kpi_code, temp_code, temp_score_b, user_dep) VALUES (?, ?, ?, ?, ?, ?)`,
            [score_date, scoreNumber, kpi_code, temp_code, score_b, user_dep]
          );
        } else if (score_a !== "" && score_b === "") {
          await localPool.query(
            `INSERT INTO tb_score (score_date, score_number, kpi_code, temp_code, temp_score_a, user_dep) VALUES (?, ?, ?, ?, ?, ?)`,
            [score_date, scoreNumber, kpi_code, temp_code, score_a, user_dep]
          );
        } else if (score_a !== "" && score_b !== "") {
          await localPool.query(
            `INSERT INTO tb_score (score_date, score_number, kpi_code, temp_code, temp_score_a, temp_score_b, user_dep) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
              score_date,
              scoreNumber,
              kpi_code,
              temp_code,
              score_a,
              score_b,
              user_dep,
            ]
          );
        }
      } else {
        if (score_a === "" && score_b !== "") {
          await localPool.query(
            "UPDATE tb_score SET temp_score_b = ?, temp_score_a = null WHERE kpi_code = ? AND score_date = ? AND temp_code = ? AND user_dep = ?",
            [score_b, kpi_code, score_date, temp_code, user_dep]
          );
          console.log(
            `Updated: ${kpi_code}, ${temp_code}, ${score_date}, temp_score_a: ${score_a}, temp_score_b: ${score_b}, user_dep: ${user_dep}`
          );
        } else if (score_a !== "" && score_b === "") {
          console.log("test");
          await localPool.query(
            "UPDATE tb_score SET temp_score_a = ?, temp_score_b = null WHERE kpi_code = ? AND score_date = ? AND temp_code = ? AND user_dep = ?",
            [score_a, kpi_code, score_date, temp_code, user_dep]
          );
          console.log(
            `Updated: ${kpi_code}, ${temp_code}, ${score_date}, temp_score_a: ${score_a}, temp_score_b: ${score_b}, user_dep: ${user_dep}`
          );
        } else if (score_a !== "" && score_b !== "") {
          await localPool.query(
            "UPDATE tb_score SET temp_score_a = ?, temp_score_b = ? WHERE kpi_code = ? AND score_date = ? AND temp_code = ? AND user_dep = ?",
            [score_a, score_b, kpi_code, score_date, temp_code, user_dep]
          );
          console.log(
            `Updated: ${kpi_code}, ${temp_code}, ${score_date}, temp_score_a: ${score_a}, temp_score_b: ${score_b}, user_dep: ${user_dep}`
          );
        } else if (score_a == "" && score_b == "") {
          await localPool.query(
            "UPDATE tb_score SET temp_score_a = null, temp_score_b = null WHERE kpi_code = ? AND score_date = ? AND temp_code = ? AND user_dep = ?",
            [kpi_code, score_date, temp_code, user_dep]
          );
        }
      }
      insertedRecords.push({
        score_number: scoreNumber,
        kpi_code,
        temp_code,
        score_a,
        score_b,
      });
    }

    res
      .status(200)
      .json({ message: "Data inserted successfully", insertedRecords });
  } catch (error) {
    console.error("Error processing submission:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

async function getNextScoreNumber(base) {
  const [rows] = await localPool.query(
    `SELECT score_number FROM tb_score WHERE score_number LIKE ? ORDER BY score_number DESC LIMIT 1`,
    [`${base}S%`]
  );

  if (rows.length > 0) {
    const lastScore = rows[0].score_number;
    const lastNumber = parseInt(lastScore.slice(-6)) + 1; // Extract and increment the last number
    const nextNumber = `${base}S${String(lastNumber).padStart(6, "0")}`; // Format with leading zeros
    return nextNumber;
  }

  return `${base}S000001`;
}

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
