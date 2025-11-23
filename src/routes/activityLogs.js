import express from "express";
import supabase from "../config/supabase.js";
import { authenticateToken } from "../middlewares/auth.js";

const router = express.Router();

/**
 * @route   GET /:dogId
 * @desc    Get recent activity logs for a dog.
 * @access  Private
 */
router.get("/:dogId", authenticateToken, async (req, res) => {
    const { dogId } = req.params;

    try {
        const { data, error } = await supabase
            .from("activity_logs")
            .select("*")
            .eq("dog_id", dogId)
            .order("occurred_at", { ascending: false });

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to retrieve activity logs",
            });
        }

        return res.status(200).json({
            message: `Activity history for dog ${dogId} retrieved successfully.`,
            data: data || [],
        });
    } catch (error) {
        console.error("Get activity logs error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

/**
 * @route   GET /:logId
 * @desc    Get a specific activity log entry.
 * @access  Private
 */
router.get("/:logId", authenticateToken, async (req, res) => {
    const { logId } = req.params;

    try {
        const { data, error } = await supabase
            .from("activity_logs")
            .select("*")
            .eq("id", logId)
            .single();

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to retrieve activity log",
            });
        }

        return res.status(200).json({
            message: `Activity log ${logId} retrieved successfully.`,
            data: data || [],
        });
    } catch (error) {
        console.error("Get activity log error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

/**
 * @route   POST /
 * @desc    Create a new activity log.
 * @access  Private
 */
router.post("/", authenticateToken, async (req, res) => {
    const { dog_id, activity_type, note, occurred_at } = req.body;

    if (!dog_id || !activity_type) {
        return res.status(400).json({
            error: "Missing required fields: dog_id and activity_type are required.",
        });
    }

    try {
        const { data, error } = await supabase
            .from("activity_logs")
            .insert({
                dog_id,
                activity_type,
                note,
                occurred_at: occurred_at || new Date().toISOString(),
            })
            .select()
            .single();

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to create activity log",
            });
        }

        return res.status(201).json({
            message: "Activity logged successfully.",
            data: data,
        });
    } catch (error) {
        console.error("Create log error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * @route   DELETE /:logId
 * @desc    Deletes a specific activity log entry.
 * @access  Private
 */
router.delete("/:logId", authenticateToken, async (req, res) => {
    const { logId } = req.params;

    try {
        const { data, error } = await supabase
            .from("activity_logs")
            .delete()
            .eq("id", logId);

        if (error || !data) {
            return res.status(404).json({
                error: "Activity log not found",
            });
        }

        return res.status(200).json({
            message: "Activity log deleted successfully",
        });
    } catch (error) {
        console.error("Delete log error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

export default router;
