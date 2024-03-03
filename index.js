import express from "express";
import { dirname } from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bycryptjs from "bcryptjs";
import bodyParser from "body-parser";
import session from "express-session";
import passport, { Passport } from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";

import { User } from "./models/User.js";
import { access } from "fs";
dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("DB connected successfully");
  });

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));

const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.get("/signUp", (req, res) => {
  res.sendFile(__dirname + "/public/signUp.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

app.get("/site", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.sendFile(__dirname + "/public/site.html");
  } else {
    res.sendFile(__dirname + "/public/login.html");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/home",
  passport.authenticate("google", {
    successRedirect: "/site",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/")
  })
})

app.post("/signUp", (req, res) => {
  const { fName, lName, email, password } = req.body;
  if (fName == "" || lName == "" || email == "" || password == "") {
    res.json({
      status: "Failed",
      info: "Empty credentials submitted",
    });
  } else if (password.length < 8) {
    res.json({
      status: "Failed",
      info: "Password is too short",
    });
  } else {
    User.findOne({ email }).then((result) => {
      if (result) {
        res.json({
          status: "Failed",
          info: "User with User Name or Email already exists",
        });
      } else {
        bycryptjs.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            res.json({
              status: "Failed",
              info: err,
            });
          }

          const newUser = new User({
            fName,
            lName,
            email,
            password: hash,
          });
          newUser
            .save()
            .then(() => {
              res.sendFile(__dirname + "/public/login.html");
            })
            .catch((err) => {
              res.json({
                status: "Failed",
                info: err,
              });
            });
        });
      }
    });
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/site",
    failureRedirect: "/login",
  })
);

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    console.log(username);

    try {
      const result = await User.find({ username });
      const data = result[0];
      if (data) {
        console.log(data);
        const userPass = data.password;
        bycryptjs.compare(password, userPass, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, data);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (error) {
      return cb(error);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/home",
      userProfileURL: "https://www.googleapis.com/oauth2/v4/user",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      try {
        const existingUser = await User.find({ email: profile.email });
        if (!existingUser) {
          const newUser = new User(
            {
              email: profile.email,
              password: "google",
            }
          );
          await newUser.save();
          cb(null, newUser);
        } else {
          cb(null, existingUser);
        }
      } catch (error) {
        cb(error);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
