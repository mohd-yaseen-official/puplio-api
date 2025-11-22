import supabase from "../config/supabase.js";

/**
 * Middleware to check if user is authenticated
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 * @param {NextFunction} next - Express next function
 */
export const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers["authorization"];
        const token = authHeader?.startsWith("Bearer ")
            ? authHeader.split(" ")[1]
            : null;

        if (!token) {
            return res.status(401).json({
                error: "Access token required",
            });
        }

        const { data, error } = await supabase.auth.getUser(token);

        if (error || !data?.user) {
            return res.status(403).json({
                error: "Invalid or expired token",
            });
        }

        req.user = data.user;
        next();
    } catch (error) {
        console.error("Authentication error:", error);
        return res.status(500).json({
            error: "Internal server error during authentication",
        });
    }
};
