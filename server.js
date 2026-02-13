const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const authMiddleware = require("./middleware/auth");
const requestLogger = require("./middleware/logger");
const app = express();
const port = 3000;

app.use(express.json())
app.use(cookieParser());
app.user(requestLogger)
const loginSessions = {};
const otpStore = {};

app.post('/auth/login',(req,res)=>{
    const {email,password} = req.body
    if (!email || !password){
        return res.json({
            error : 'email and passowrd is required'
        })
    }
    const loginSessionId = Math.random().toString(36).substring(2, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    loginSessions[loginSessionId] = {
        email,
        createdAt: Date.now(),
        expiresAt: Date.now() + 2 * 60 * 1000,
    }
    otpStore[loginSessionId] = otp;
    console.log(`[OTP] Session ${loginSessionId} generated. OTP: ${otp}`);
    return res.status(200).json({
      message: "OTP sent",
      loginSessionId,
      otp
    });

})


app.post("/auth/verify-otp", (req, res) => {
  try {
    const { loginSessionId, otp } = req.body;

    if (!loginSessionId || !otp) {
      return res.status(400).json({
        error: "loginSessionId and otp required"
      });
    }

    const session = loginSessions[loginSessionId];

    if (!session) {
      return res.status(401).json({ error: "Invalid session" });
    }

    if (Date.now() > session.expiresAt) {
      delete loginSessions[loginSessionId];
      delete otpStore[loginSessionId];
      return res.status(401).json({ error: "Session expired" });
    }

    if (otp !== otpStore[loginSessionId]) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    res.cookie("session_token", loginSessionId, {
      httpOnly: true,
      secure: false,
      maxAge: 15 * 60 * 1000,
    });

    delete otpStore[loginSessionId];

    return res.status(200).json({
      message: "OTP verified",
      sessionId: loginSessionId,
    });

  } catch (error) {
    return res.status(500).json({
      status: "error",
      message: "OTP verification failed",
    });
  }
});

app.post("/auth/token", (req, res) => {
  try {
    const sessionId = req.cookies.session_token;

    if (!sessionId) {
      return res
        .status(401)
        .json({ error: "Unauthorized - valid session required" });
    }

    const session = loginSessions[sessionId];

    if (!session) {
      return res.status(401).json({ error: "Invalid session" });
    }

    const secret = process.env.JWT_SECRET || "default-secret-key";

    const accessToken = jwt.sign(
      {
        email: session.email,
        sessionId: sessionId,
      },
      secret,
      {
        expiresIn: "15m",
      }
    );

    return res.status(200).json({
      access_token: accessToken,
      expires_in: 900,
    });

  } catch (error) {
    return res.status(500).json({
      status: "error",
      message: "Token generation failed",
    });
  }
});


app.get("/protected", authMiddleware, (req, res) => {
  return res.json({
    message: "Access granted",
    user: req.user,
    success_flag: `FLAG-${Buffer.from(req.user.email + "_COMPLETED_ASSIGNMENT").toString('base64')}`,
  });
});


app.listen(3000,()=>{
    console.log('Server is Running on port 3000')
})
