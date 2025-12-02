import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload as BaseJwtPayload, VerifyErrors } from "jsonwebtoken";
import { prisma } from "../lib/prisma";

interface JwtPayload extends BaseJwtPayload {
    userId: string;
}

type AuthenticatedRequest = Request & {
    user?: {
        id: string;
        email: string;
    };
};

/**
 * Middleware to check if user is authenticated
 */
export const authenticateToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const authHeader = req.headers["authorization"];
        const token = authHeader?.startsWith("Bearer ")
            ? authHeader.split(" ")[1]
            : null;

        if (!token) {
            res.status(401).json({
                error: "Access token required",
            });
            return;
        }

        if (!process.env.ACCESS_TOKEN_SECRET) {
            throw new Error("ACCESS_TOKEN_SECRET is not defined");
        }

        let decoded: JwtPayload;
        try {
            decoded = jwt.verify(
                token,
                process.env.ACCESS_TOKEN_SECRET as string
            ) as JwtPayload;
        } catch (err) {
            res.status(403).json({ error: "Invalid or expired token" });
            return;
        }

        const { userId } = decoded;

        try {
            const user = await prisma.user.findUnique({
                where: { id: userId },
                select: { id: true, email: true },
            });

            if (!user) {
                res.status(404).json({ error: "User not found" });
                return;
            }

            req.user = user;
            next();
        } catch (dbError) {
            console.error("Database error:", dbError);
            res.status(500).json({ error: "Internal server error" });
        }
    } catch (error) {
        console.error("Authentication error:", error);
        res.status(500).json({
            error: "Internal server error during authentication",
        });
    }
};
