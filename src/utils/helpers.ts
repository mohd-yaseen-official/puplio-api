import jwt from "jsonwebtoken";

interface TokenPair {
    accessToken: string;
    refreshToken: string;
}

export const generateTokens = (userId: string): TokenPair => {
    const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
    const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;

    if (!accessTokenSecret || !refreshTokenSecret) {
        throw new Error("Missing token secrets in environment variables");
    }

    const accessToken = jwt.sign({ userId }, accessTokenSecret, {
        expiresIn: "15m",
    });

    const refreshToken = jwt.sign({ userId }, refreshTokenSecret, {
        expiresIn: "7d",
    });

    return { accessToken, refreshToken };
};
