import express from "express";
import bcript from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JWTStrategy, ExtractJwt } from "passport-jwt";
import jwt from 'jsonwebtoken'

const app = express();
app.use(express.json());

interface User {
  id: Number;
  username: string;
  password: string;
}
let mockUser: User
(async ()=>{
    let pass = await bcript.hash("test", 42)
    mockUser =  {
        id: 123,
        username: "test",
        password: pass,
      };
})();


passport.use(
  new LocalStrategy(async (username: string, password: string, done: Function) => {
    try {
      if (username != mockUser.username) {
        return done(null, false, { message: "not user" });
      }
      const correctPassword = await bcript.compare(password, mockUser.password);
      if (!correctPassword) {
        return done(null, false, { message: "wrong password" });
      }
      return done(null, mockUser);
    } catch (err) {
      return done(err);
    }
  })
);

passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET!,
    },
    (payload, done) => {
      if (payload.sub == mockUser.id) {
        return done(null, mockUser);
      }
      return done(null, false);
    }
  )
);

app.post(
  "/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    const token = jwt.sign(
      { sub: mockUser.id },
      process.env.JWT_SECRET!,
      { expiresIn: "1h" }
    );
    res.cookie("accessToken", token);
    res.json({ accessToken: token });
  }
);

app.checkout(
  "/profile",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({
      user: {
        id: mockUser.id,
        username:mockUser.username,
      },
    });
  }
);

app.listen(3000, () => {
  console.log("server at 3000");
});
