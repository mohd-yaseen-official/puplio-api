import express, { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";
import { authenticateToken } from "../middlewares/auth";
import { generateTokens } from "../utils/helpers";

const router = express.Router();

interface SignupRequestBody {
    email: string;
    password: string;
}

interface LoginRequestBody {
    email: string;
    password: string;
}

interface RefreshTokenRequestBody {
    refresh_token?: string;
}

type AuthenticatedRequest = Request & {
    user?: {
        id: string;
        email: string;
    };
};

/**
 * @route   POST /signup
 * @desc    Register a new user
 * @access  Public
 */
router.post(
    "/signup",
    async (req: Request<{}, {}, SignupRequestBody>, res: Response) => {
        try {
            const { email, password } = req.body;

            if (!email || !password) {
                return res
                    .status(400)
                    .json({ error: "Email and password are required" });
            }

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ error: "Invalid email format" });
            }

            if (password.length < 8) {
                return res.status(400).json({
                    error: "Password must be at least 8 characters long",
                });
            }

            const existingUser = await prisma.user.findUnique({
                where: { email },
            });
            if (existingUser) {
                return res.status(409).json({ error: "User already exists" });
            }

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            const newUser = await prisma.user.create({
                data: {
                    email,
                    password: hashedPassword,
                },
            });

            return res.status(201).json({
                message: "User created successfully. You can now login.",
                user: {
                    id: newUser.id,
                    email: newUser.email,
                },
            });
        } catch (error) {
            console.error("Signup error:", error);

            const maybePrismaError = error as { code?: string };

            if (maybePrismaError.code === "P2002") {
                return res.status(409).json({ error: "User already exists" });
            }

            return res.status(500).json({ error: "Internal server error" });
        }
    }
);

/**
 * @route   POST /login
 * @desc    Login user
 * @access  Public
 */
router.post(
    "/login",
    async (req: Request<{}, {}, LoginRequestBody>, res: Response) => {
        try {
            const { email, password } = req.body;

            if (!email || !password) {
                return res
                    .status(400)
                    .json({ error: "Email and password are required" });
            }

            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) {
                return res.status(401).json({ error: "Invalid credentials" });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: "Invalid credentials" });
            }

            const { accessToken, refreshToken } = generateTokens(user.id);

            await prisma.refreshToken.create({
                data: {
                    token: refreshToken,
                    userId: user.id,
                },
            });

            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                maxAge: 7 * 24 * 60 * 60 * 1000,
                sameSite: "strict",
            });

            return res.status(200).json({
                message: "Login successful",
                access_token: accessToken,
                user: {
                    id: user.id,
                    email: user.email,
                },
            });
        } catch (error) {
            console.error("Login error:", error);
            return res.status(500).json({ error: "Internal server error" });
        }
    }
);

/**
 * @route   POST /refresh-token
 * @desc    Refresh access token
 * @access  Public
 */
router.post(
    "/refresh-token",
    async (req: Request<{}, {}, RefreshTokenRequestBody>, res: Response) => {
        try {
            const refreshToken =
                req.cookies?.refreshToken || req.body.refresh_token;

            if (!refreshToken) {
                return res
                    .status(401)
                    .json({ error: "Refresh token is required" });
            }

            const storedToken = await prisma.refreshToken.findUnique({
                where: { token: refreshToken },
                include: { user: true },
            });

            if (!storedToken) {
                res.clearCookie("refreshToken");
                return res.status(403).json({ error: "Invalid refresh token" });
            }

            jwt.verify(
                refreshToken,
                process.env.REFRESH_TOKEN_SECRET!,
                (
                    err: jwt.VerifyErrors | null,
                    decoded: jwt.JwtPayload | string | undefined
                ) => {
                    if (
                        err ||
                        (typeof decoded === "object" &&
                            decoded?.userId !== storedToken.userId)
                    ) {
                        prisma.refreshToken
                            .delete({ where: { token: refreshToken } })
                            .catch(() => {});
                        res.clearCookie("refreshToken");
                        return res
                            .status(403)
                            .json({ error: "Expired or invalid token" });
                    }

                    const newAccessToken = jwt.sign(
                        { userId: storedToken.user.id },
                        process.env.ACCESS_TOKEN_SECRET!,
                        { expiresIn: "15m" }
                    );

                    return res.status(200).json({
                        access_token: newAccessToken,
                    });
                }
            );
        } catch (error) {
            console.error("Refresh token error:", error);
            return res.status(500).json({ error: "Internal server error" });
        }
    }
);

/**
 * @route   POST /logout
 * @desc    Logout user
 * @access  Private
 */
router.post(
    "/logout",
    authenticateToken,
    async (req: Request, res: Response) => {
        try {
            const refreshToken = req.cookies?.refreshToken;

            if (refreshToken) {
                await prisma.refreshToken.deleteMany({
                    where: { token: refreshToken },
                });
                res.clearCookie("refreshToken");
            }

            return res.status(200).json({ message: "Logout successful" });
        } catch (error) {
            console.error("Logout error:", error);
            return res.status(500).json({ error: "Internal server error" });
        }
    }
);

/**
 * @route   POST /delete
 * @desc    Delete the currently logged in user
 * @access  Private
 */
router.post(
    "/delete",
    authenticateToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            if (!req.user) {
                return res.status(401).json({ error: "Unauthorized" });
            }

            const userId = req.user.id;

            await prisma.refreshToken.deleteMany({
                where: { userId: userId },
            });

            res.clearCookie("refreshToken");

            await prisma.user.delete({
                where: { id: userId },
            });

            return res
                .status(200)
                .json({ message: "User deleted successfully" });
        } catch (error) {
            console.error("Delete user error:", error);
            return res.status(500).json({ error: "Internal server error" });
        }
    }
);

export default router;
