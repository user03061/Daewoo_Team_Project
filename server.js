const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const session = require("express-session");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const http = require("http");
const app = express();
const cors = require("cors");
app.use(cors());

const activeChats = new Map();

// 세션 미들웨어 설정
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// body-parser 설정
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ limit: "10mb", extended: true }));
app.use(express.static("public"));

// MySQL 연결 설정
const db = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  password: "1234",
  database: "test",
});

db.connect((err) => {
  if (err) {
    console.error("MySQL 연결 오류:", err);
    return;
  }
  console.log("MySQL에 연결되었습니다.");
});

const checkAuth = (req, res, next) => {
  console.log("Session:", req.session);
  if (req.session.user) {
    console.log("User authenticated:", req.session.user);
    next();
  } else {
    console.log("User not authenticated");
    res.status(401).json({ error: "Authentication required" });
  }
};

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "MBTITest.html"));
});

// main.html 페이지 접근 제한
app.get("/main.html", checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "main.html"));
});

app.get("/api/check-auth", (req, res) => {
  if (req.session.user) {
    res.json({
      isLoggedIn: true,
      user: {
        name: req.session.user.name,
        email: req.session.user.email,
      },
    });
  } else {
    res.json({ isLoggedIn: false });
  }
});

// 회원가입
app.post("/signup", (req, res) => {
  const { name, email, gender, age_range, password, confirm_password } =
    req.body;
  const upperGender = gender.toUpperCase();

  if (password !== confirm_password) {
    return res.status(400).json({ message: "비밀번호가 일치하지 않습니다." });
  }
  const validAgeRanges = [
    "0-12",
    "13-18",
    "19-24",
    "25-29",
    "30-34",
    "35-39",
    "40-44",
    "45-49",
    "50+",
  ];
  if (!validAgeRanges.includes(age_range)) {
    return res.status(400).json({ message: "유효하지 않은 나이 범위입니다." });
  }
  const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
  db.query(checkEmailQuery, [email], (err, results) => {
    if (err) {
      console.error("이메일 중복 체크 오류:", err);
      return res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }
    if (results.length > 0) {
      return res.status(400).json({ message: "이미 사용 중인 이메일입니다." });
    }
    const insertQuery =
      "INSERT INTO users (name, email, gender, age_range, password) VALUES (?, ?, ?, ?, ?)";
    db.query(
      insertQuery,
      [name, email, upperGender, age_range, password],
      (err, result) => {
        if (err) {
          console.error("데이터베이스 삽입 오류:", err);
          return res
            .status(500)
            .json({ message: "서버 오류가 발생했습니다.", error: err.message });
        }
        console.log("회원가입 성공. 삽입된 행 ID:", result.insertId);
        res.json({ message: "회원가입이 완료되었습니다." });
      }
    );
  });
});

// 로그인
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const query = "SELECT * FROM users WHERE email = ? AND password = ?";
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error("데이터베이스 오류:", err);
      return res.status(500).send("서버 오류가 발생했습니다.");
    }

    if (results.length > 0) {
      req.session.user = {
        id: results[0].id,
        name: results[0].name,
        email: results[0].email,
      };
      req.session.save((err) => {
        if (err) {
          console.error("세션 저장 오류:", err);
          return res.status(500).send("서버 오류가 발생했습니다.");
        }
        res.redirect("/MBTITest.html");
      });
    } else {
      res.status(401).send("아이디 또는 비밀번호가 올바르지 않습니다.");
    }
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return console.log(err);
    }
    res.redirect("/");
  });
});

// 관리자 로그인
app.post("/admin-login", (req, res) => {
  const { email, password } = req.body;

  const query = "SELECT * FROM admins WHERE email = ? AND password = ?";
  db.query(query, [email, password], (err, results) => {
    if (err) {
      console.error("데이터베이스 오류:", err);
      return res.status(500).send("서버 오류가 발생했습니다.");
    }

    if (results.length > 0) {
      req.session.admin = {
        email: results[0].email,
      };
      res.redirect("/admin.html");
    } else {
      res.status(401).send("아이디 또는 비밀번호가 올바르지 않습니다.");
    }
  });
});

// 연령대별 성별 통계
app.get("/api/age-gender-stats", (req, res) => {
  const query = `
        SELECT 
            age_range AS age_group,
            COUNT(*) as total_count,
            SUM(CASE WHEN gender = 'm' THEN 1 ELSE 0 END) AS male_count,
            SUM(CASE WHEN gender = 'w' THEN 1 ELSE 0 END) AS female_count
        FROM users
        WHERE age_range IN ('13-18', '19-24', '25-29', '30-34', '35-39', '40-44', '45-49', '50+')
        GROUP BY age_range
        ORDER BY FIELD(age_range, '13-18', '19-24', '25-29', '30-34', '35-39', '40-44', '45-49', '50+');
    `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("데이터베이스 오류:", err);
      return res.status(500).send("서버 오류가 발생했습니다.");
    }

    const data = results.map((row) => ({
      ageGroup: row.age_group,
      male: parseFloat(((row.male_count / row.total_count) * 100).toFixed(1)),
      female: parseFloat(
        ((row.female_count / row.total_count) * 100).toFixed(1)
      ),
    }));

    res.json(data);
  });
});

// MBTI 통계 API
app.get("/api/mbti-stats", (req, res) => {
  const query = `
        SELECT mbti_result, COUNT(*) as count
        FROM users
        WHERE mbti_result IS NOT NULL
        GROUP BY mbti_result
    `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("MBTI 통계 조회 오류:", err);
      return res.status(500).json({ error: "서버 오류가 발생했습니다." });
    }

    const totalUsers = results.reduce((sum, row) => sum + row.count, 0);
    const mbtiStats = {};

    results.forEach((row) => {
      mbtiStats[row.mbti_result] = row.count;
    });

    console.log({ stats: mbtiStats, totalUsers });

    if (Object.keys(mbtiStats).length === 0) {
      return res.status(404).json({ message: "MBTI 데이터가 없습니다." });
    }

    res.json({ stats: mbtiStats, totalUsers });
  });
});

// MBTI 결과 저장
app.post("/save-mbti-result", async (req, res) => {
  if (!req.session.user) {
    console.log("Unauthorized attempt to save MBTI result");
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const { mbtiResult } = req.body;
  const userId = req.session.user.id;

  console.log("Saving MBTI result:", mbtiResult, "for user:", userId);

  try {
    // MBTI 결과 저장
    const query = "UPDATE users SET mbti_result = ? WHERE id = ?";
    const [result] = await db.promise().query(query, [mbtiResult, userId]);

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ success: false, message: "사용자를 찾을 수 없습니다." });
    }

    res.json({ success: true, message: "MBTI 결과가 저장되었습니다." });
  } catch (error) {
    console.error("오류 발생:", error);
    res
      .status(500)
      .json({ success: false, message: "서버 오류가 발생했습니다." });
  }
});

app.post("/send-result-mbti", async (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const { mbtiResult, resultDescription } = req.body;
  const userEmail = req.session.user.email;

  //메일보내는 함수
  const mailOptions = {
    from: "your-email@gmail.com",
    to: userEmail,
    subject: "당신의 MBTI 결과",
    html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background-color:black;">
        <div style="text-align: center; margin-bottom: 20px;">
        <div style="display: inline-block; background-color: white; padding: 10px 20px; border-radius: 10px;">
            <span style="font-size: 48px; font-weight: bold; color: #2178a3;">My</span><span style="font-size: 48px; font-weight: bold; color: #72138f;">BTI</span>
        </div>
        </div>
        
        <div style="padding: 20px; background-color: #ffffff; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
                <div style="margin-top: 20px;">
                    ${resultDescription
                      .replace(`${mbtiResult}: `, "")
                      .split(". ")
                      .map(
                        (sentence) =>
                          `<p style="line-height: 1.6; font-size: 14px;">${sentence.trim()}.</p>`
                      )
                      .join("")}
                </div>
        </div>

        <p style="text-align: center; margin-top: 20px; color: white;">더 많은 정보를 원하시면 <a href="https://3c21-121-130-31-60.ngrok-free.app/main.html" style="color: #19d5ff; text-decoration: none;">우리 웹사이트</a>를 방문해보세요!</p>
        </div>
        `,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({
      success: true,
      message: "MBTI 결과가 이메일로 전송되었습니다.",
    });
  } catch (error) {
    console.error("이메일 전송 오류:", error);
    res
      .status(500)
      .json({ success: false, message: "이메일 전송 중 오류가 발생했습니다." });
  }
});

// 일반적인 SMTP 설정 (예: Gmail)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "leejh010510@gmail.com",
    pass: "clci dhfq mais zfzv",
  },
});

app.get("/MBTITest.html", checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "MBTITest.html"));
});

app.get("/get-user-profile", (req, res) => {
  const userId = req.session.user.id;
  const query =
    "SELECT name, school, job, birthday, bio, gender, profile_photo, interests FROM users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res
        .status(500)
        .json({ success: false, message: "서버 오류가 발생했습니다." });
    }

    if (results.length > 0) {
      console.log("User profile data:", results[0]);
      res.json({ success: true, ...results[0] });
    } else {
      console.log("User profile not found for id:", userId);
      res
        .status(404)
        .json({ success: false, message: "사용자 프로필을 찾을 수 없습니다." });
    }
  });
});

app.get("/get-mbti-result", (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const userId = req.session.user.id;
  const query = "SELECT mbti_result FROM users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("데이터베이스 오류:", err);
      return res
        .status(500)
        .json({ success: false, message: "서버 오류가 발생했습니다." });
    }

    if (results.length > 0 && results[0].mbti_result) {
      res.json({ success: true, mbtiResult: results[0].mbti_result });
    } else {
      res
        .status(404)
        .json({ success: false, message: "MBTI 결과를 찾을 수 없습니다." });
    }
  });
});

//랜덤사용자 가져오기
app.get("/api/random-profiles", (req, res) => {
  const count = parseInt(req.query.count) || 3;
  const currentUserId = req.session.user ? req.session.user.id : null;

  const query = `
        SELECT id, name, school, job, birthday, bio, gender, profile_photo, interests, mbti_result
        FROM users
        WHERE id != ?
        ORDER BY RAND()
        LIMIT ?
    `;

  db.query(query, [currentUserId, count], (err, results) => {
    if (err) {
      console.error("Error fetching random profiles:", err);
      return res
        .status(500)
        .json({ success: false, message: "Internal server error" });
    }

    // 비밀번호 등 민감한 정보 제거
    const profiles = results.map((profile) => {
      const { password, ...safeProfile } = profile;
      return safeProfile;
    });

    res.json({ success: true, profiles });
  });
});

// 사용자 정보 제공
app.get("/api/user-info", (req, res) => {
  if (req.session.user) {
    res.json({ name: req.session.user.name });
  } else {
    res.status(401).json({ error: "인증되지 않은 사용자" });
  }
});

// 관리자 페이지 접근 제한
app.use("/admin.html", (req, res, next) => {
  if (req.session.admin) {
    next();
  } else {
    res.redirect("/login2.html");
  }
});

app.get("/admin.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("서버 오류가 발생했습니다.");
});

// 서버 시작
const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`서버가 http://0.0.0.0:${PORT} 에서 실행 중입니다.`);
});

// 업로드 디렉토리 설정 및 생성
const uploadDir = path.join(__dirname, "uploads");
const postUploadDir = path.join(uploadDir, "posts");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
if (!fs.existsSync(postUploadDir)) {
  fs.mkdirSync(postUploadDir, { recursive: true });
}

// multer 설정
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, `profile-${Date.now()}${path.extname(file.originalname)}`);
  },
});
const upload = multer({ storage: storage });

// 게시글 이미지를 위한 multer 설정
const postImageStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, postUploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, `post-${Date.now()}${path.extname(file.originalname)}`);
  },
});
const uploadPostImage = multer({ storage: postImageStorage });

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// save-profile 라우트 수정
app.post("/save-profile", upload.single("profilePhoto"), (req, res) => {
  const { name, gender, school, job, birthday, bio, interests } = req.body;
  const upperGender = gender ? gender.toUpperCase() : null; // 성별이 존재할 경우에만 대문자로 변환
  const profilePhotoPath = req.file ? `/uploads/${req.file.filename}` : null;

  if (!req.session.user || !req.session.user.id) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  let query =
    "UPDATE users SET name = ?, school = ?, job = ?, birthday = ?, bio = ?, interests = ?";
  const queryParams = [name, school, job, birthday, bio, interests];

  if (upperGender !== null) {
    query += ", gender = ?";
    queryParams.push(upperGender);
  }

  if (profilePhotoPath) {
    query += ", profile_photo = ?";
    queryParams.push(profilePhotoPath);
  }

  query += " WHERE id = ?";
  queryParams.push(req.session.user.id);

  db.query(query, queryParams, (err, result) => {
    if (err) {
      console.error("DB 업데이트 중 오류 발생:", err);
      return res
        .status(500)
        .json({ success: false, message: "서버 오류가 발생했습니다." });
    }
    res.json({ success: true });
  });
});

// 프로필 페이지 라우트
app.get("/profile.html", (req, res) => {
  const userId = req.session.user.id;
  const query = "SELECT * FROM users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("서버 오류가 발생했습니다.");
    }
    const user = results[0];
    res.render("profile", { user });
  });
});

// 메시지 전송 API
app.post("/api/send-message", (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const { receiverId, message } = req.body;
  const senderId = req.session.user.id;

  const query =
    "INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)";
  db.query(query, [senderId, receiverId, message], (err, result) => {
    if (err) {
      console.error("메시지 전송 오류:", err);
      return res
        .status(500)
        .json({ success: false, message: "메시지 전송 실패" });
    }
    res.json({ success: true, message: "메시지 전송 성공" });
  });
});

// 메시지 조회 API
app.get("/api/get-messages", (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const { partnerId } = req.query;
  const userId = req.session.user.id;

  const query = `
        SELECT * FROM chat_messages 
        WHERE (sender_id = ? AND receiver_id = ?) 
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    `;
  db.query(query, [userId, partnerId, partnerId, userId], (err, results) => {
    if (err) {
      console.error("메시지 조회 오류:", err);
      return res
        .status(500)
        .json({ success: false, message: "메시지 조회 실패" });
    }
    res.json({ success: true, messages: results, currentUserId: userId });
  });
});

//메시지 기록 가져오기
app.get("/api/chat-partners", (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const userId = req.session.user.id;

  const query = `
        SELECT u.id AS partner_id, u.name AS partner_name
        FROM chat_messages cm
        JOIN users u ON u.id = CASE 
            WHEN cm.sender_id = ? THEN cm.receiver_id 
            ELSE cm.sender_id 
        END
        WHERE (cm.sender_id = ? AND cm.deleted_by_sender = FALSE) 
           OR (cm.receiver_id = ? AND cm.deleted_by_receiver = FALSE)
        GROUP BY u.id, u.name
    `;

  db.query(query, [userId, userId, userId], (err, results) => {
    if (err) {
      console.error("채팅 상대 목록 조회 오류:", err);
      return res
        .status(500)
        .json({ success: false, message: "서버 오류가 발생했습니다." });
    }
    res.json({ success: true, partners: results });
  });
});

//채팅방 나가기
app.post("/api/leave-chat", (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const userId = req.session.user.id;
  const { partnerId } = req.body;

  const query = `
        UPDATE chat_messages
        SET 
            deleted_by_sender = CASE WHEN sender_id = ? THEN TRUE ELSE deleted_by_sender END,
            deleted_by_receiver = CASE WHEN receiver_id = ? THEN TRUE ELSE deleted_by_receiver END
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
    `;

  db.query(
    query,
    [userId, userId, userId, partnerId, partnerId, userId],
    (err, result) => {
      if (err) {
        console.error("방 나가기 오류:", err);
        return res
          .status(500)
          .json({ success: false, message: "방 나가기 실패" });
      }

      res.json({ success: true, message: "방 나가기가 완료되었습니다." });
    }
  );
});

app.get("/api/get-mbti-messages", (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const { roomId } = req.query;
  const userId = req.session.user.id;

  const query = `
        SELECT m.*, u.name as sender_name
        FROM messages m
        JOIN users u ON m.userId = u.id
        WHERE m.roomId = ?
        ORDER BY m.timestamp ASC
    `;

  db.query(query, [roomId], (err, results) => {
    if (err) {
      console.error("MBTI 채팅 메시지 조회 오류:", err);
      return res
        .status(500)
        .json({ success: false, message: "MBTI 채팅 메시지 조회 실패" });
    }
    res.json({ success: true, messages: results, currentUserId: userId });
  });
});

app.post("/api/send-mbti-message", (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const { roomId, message } = req.body;
  const userId = req.session.user.id;

  const query =
    "INSERT INTO messages (roomId, userId, message) VALUES (?, ?, ?)";
  db.query(query, [roomId, userId, message], (err, result) => {
    if (err) {
      console.error("MBTI 메시지 전송 오류:", err);
      return res
        .status(500)
        .json({ success: false, message: "MBTI 메시지 전송 실패" });
    }
    res.json({ success: true, message: "MBTI 메시지 전송 성공" });
  });
});

// 이름으로 프로필 검색 API 추가
app.get("/api/search-profiles", (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "로그인이 필요합니다." });
  }

  const { name } = req.query;
  const currentUserId = req.session.user.id;

  // 이름으로 검색하되, 현재 사용자는 제외
  const query = `
        SELECT id, name, school, job, birthday, bio, gender, profile_photo, interests, mbti_result
        FROM users
        WHERE name LIKE ? AND id != ?
        LIMIT 10
    `;

  db.query(query, [`%${name}%`, currentUserId], (err, results) => {
    if (err) {
      console.error("프로필 검색 중 오류 발생:", err);
      return res
        .status(500)
        .json({ success: false, message: "서버 오류가 발생했습니다." });
    }

    // 비밀번호 등 민감한 정보 제거
    const profiles = results.map((profile) => {
      const { password, ...safeProfile } = profile;
      return safeProfile;
    });

    res.json({ success: true, profiles });
  });
});

//게시글
app.post("/api/posts", checkAuth, (req, res) => {
  const { title, content, categories, imageUrl } = req.body;
  const userId = req.session.user.id;

  const query =
    "INSERT INTO posts (user_id, title, content, categories, image_url) VALUES (?, ?, ?, ?, ?)";
  db.query(
    query,
    [userId, title, content, categories, imageUrl],
    (err, result) => {
      if (err) {
        res.status(500).json({ error: "Database error" });
        return;
      }
      res.json({
        message: "Post created successfully",
        postId: result.insertId,
      });
    }
  );
});

// 게시글 수정
app.put("/api/posts/:id", checkAuth, (req, res) => {
  const postId = req.params.id;
  const { title, content, categories } = req.body;
  const userId = req.session.user.id;

  const query =
    "UPDATE posts SET title = ?, content = ?, categories = ? WHERE id = ? AND user_id = ?";
  db.query(
    query,
    [title, content, categories, postId, userId],
    (err, result) => {
      if (err) {
        res.status(500).json({ error: "Database error" });
        return;
      }
      if (result.affectedRows === 0) {
        res.status(403).json({ error: "Not authorized to edit this post" });
        return;
      }
      res.json({ message: "Post updated successfully" });
    }
  );
});

// 게시글 삭제
app.delete("/api/posts/:id", checkAuth, (req, res) => {
  const postId = req.params.id;
  const userId = req.session.user.id;

  console.log(`Attempting to delete post ${postId} by user ${userId}`);

  // 1. 게시글 소유권 확인
  const checkOwnershipQuery = "SELECT user_id FROM posts WHERE id = ?";
  db.query(checkOwnershipQuery, [postId], (checkErr, checkResults) => {
    if (checkErr) {
      console.error("Error checking post ownership:", checkErr);
      return res.status(500).json({ error: "Database error", details: checkErr.message });
    }

    if (checkResults.length === 0) {
      console.log(`Post ${postId} not found`);
      return res.status(404).json({ error: "Post not found" });
    }

    if (checkResults[0].user_id !== userId) {
      console.log(`User ${userId} not authorized to delete post ${postId}`);
      return res.status(403).json({ error: "Not authorized to delete this post" });
    }

    console.log(`Ownership verified for post ${postId}`);

    // 2. 관련된 좋아요 데이터 삭제
    const deleteLikesQuery = "DELETE FROM post_likes WHERE post_id = ?";
    db.query(deleteLikesQuery, [postId], (deleteLikesErr, deleteLikesResult) => {
      if (deleteLikesErr) {
        console.error("Error deleting post likes:", deleteLikesErr);
        return res.status(500).json({ error: "Database error", details: deleteLikesErr.message });
      }

      console.log(`Deleted ${deleteLikesResult.affectedRows} likes for post ${postId}`);

      // 3. 관련된 댓글 삭제
      const deleteCommentsQuery = "DELETE FROM comments WHERE post_id = ?";
      db.query(deleteCommentsQuery, [postId], (deleteCommentsErr, deleteCommentsResult) => {
        if (deleteCommentsErr) {
          console.error("Error deleting comments:", deleteCommentsErr);
          return res.status(500).json({ error: "Database error", details: deleteCommentsErr.message });
        }

        console.log(`Deleted ${deleteCommentsResult.affectedRows} comments for post ${postId}`);

        // 4. 게시글 삭제
        const deletePostQuery = "DELETE FROM posts WHERE id = ?";
        db.query(deletePostQuery, [postId], (deletePostErr, deletePostResult) => {
          if (deletePostErr) {
            console.error("Error deleting post:", deletePostErr);
            return res.status(500).json({ error: "Database error", details: deletePostErr.message });
          }

          if (deletePostResult.affectedRows === 0) {
            console.log(`No rows affected when deleting post ${postId}`);
            return res.status(404).json({ error: "Post not found or already deleted" });
          }

          console.log(`Post ${postId} successfully deleted by user ${userId}`);
          res.json({ message: "Post and related data deleted successfully" });
        });
      });
    });
  });
});

// 댓글 추가
app.post("/api/posts/:id/comments", checkAuth, (req, res) => {
  const postId = req.params.id;
  const { content } = req.body;
  const userId = req.session.user.id;

  const query =
    "INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)";
  db.query(query, [postId, userId, content], (err, result) => {
    if (err) {
      res.status(500).json({ error: "Database error" });
      return;
    }
    res.json({
      message: "Comment added successfully",
      commentId: result.insertId,
    });
  });
});

// 댓글 조회
app.get("/api/posts/:id/comments", (req, res) => {
  const postId = req.params.id;

  const query =
    "SELECT c.*, u.name as user_name FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at DESC";
  db.query(query, [postId], (err, results) => {
    if (err) {
      res.status(500).json({ error: "Database error" });
      return;
    }
    res.json(results);
  });
});

// 게시글 조회 API 수정 (정렬 추가)
app.get("/api/posts", (req, res) => {
  const sort = req.query.sort;

  let query = `
      SELECT p.*, u.name as user_name, u.profile_photo
      FROM posts p
      JOIN users u ON p.user_id = u.id
    `;

  if (sort === "popular") {
    query += "ORDER BY p.heart_count DESC";
  } else {
    query += "ORDER BY p.created_at DESC";
  }

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});

app.get("/api/current-user", (req, res) => {
  if (req.session.user) {
    res.json({ userId: req.session.user.id });
  } else {
    res.status(401).json({ error: "Not authenticated" });
  }
});

app.post(
  "/api/upload-post-image",
  uploadPostImage.single("image"),
  (req, res) => {
    if (req.file) {
      res.json({ imageUrl: `/uploads/posts/${req.file.filename}` });
    } else {
      res.status(400).json({ error: "No file uploaded" });
    }
  }
);

//프로필 게시글 가져오기
app.get("/api/user-posts", checkAuth, (req, res) => {
  const userId = req.session.user.id;
  const query = `
        SELECT p.*, u.name as user_name, u.profile_photo
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
        LIMIT 6
    `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      res.status(500).json({ error: "Database error" });
      return;
    }
    res.json(results);
  });
});

app.post("/api/posts/:postId/like", (req, res) => {
  const postId = req.params.postId;
  const userId = req.session.user.id;

  const checkLikeQuery =
    "SELECT * FROM post_likes WHERE post_id = ? AND user_id = ?";
  db.query(checkLikeQuery, [postId, userId], (err, results) => {
    if (err) {
      console.error("Error checking like status:", err);
      return res.status(500).json({ success: false, error: "Database error" });
    }

    if (results.length > 0) {
      return res.json({ success: false, alreadyLiked: true });
    }

    // 좋아요 기록 추가
    const addLikeQuery =
      "INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)";
    db.query(addLikeQuery, [postId, userId], (err, result) => {
      if (err) {
        console.error("Error adding like record:", err);
        return res
          .status(500)
          .json({ success: false, error: "Database error" });
      }

      // 게시글의 좋아요 수 증가
      const updateQuery =
        "UPDATE posts SET heart_count = heart_count + 1 WHERE id = ?";
      db.query(updateQuery, [postId], (err, result) => {
        if (err) {
          console.error("Error updating like count:", err);
          return res
            .status(500)
            .json({ success: false, error: "Database error" });
        }

        // 새로운 좋아요 수 가져오기
        const getCountQuery = "SELECT heart_count FROM posts WHERE id = ?";
        db.query(getCountQuery, [postId], (err, getResult) => {
          if (err) {
            console.error("Error getting updated like count:", err);
            return res
              .status(500)
              .json({ success: false, error: "Database error" });
          }

          // 트랜잭션 커밋 후 좋아요 처리 성공 응답
          const newHeartCount = getResult[0].heart_count;
          res.json({ success: true, newHeartCount });
        });
      });
    });
  });
});
