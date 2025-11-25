import express from "express";
import { supabase } from "../config/supabase.js";
import { authenticateToken } from "../middlewares/auth.js";
import { cleanPayload } from "../utils/helpers.js";

const router = express.Router();

/**
 * @route   GET /:dogId
 * @desc    Get all routines for a dog.
 * @access  Private
 */
router.get("/:dogId", authenticateToken, async (req, res) => {
    const { dogId } = req.params;

    try {
        const { data, error } = await supabase
            .from("routines")
            .select("*")
            .eq("dog_id", dogId)
            .order("schedule_time", { ascending: true });

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to retrieve routines",
            });
        }

        return res.status(200).json({
            message: `All routines for dog ${dogId} retrieved successfully.`,
            data: data,
        });
    } catch (error) {
        console.error("Get routines error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

/**
 * @route   POST /
 * @desc    Create a new routine for a specific dog
 * @access  Private
 */
router.post("/", authenticateToken, async (req, res) => {
    const {
        dog_id,
        title,
        activity_type,
        schedule_time,
        days_of_week,
        is_active,
    } = req.body;

    if (
        !dog_id ||
        !title ||
        !activity_type ||
        !schedule_time ||
        !days_of_week
    ) {
        return res.status(400).json({
            error: "Missing required fields: dog_id, title, activity_type, schedule_time, and days_of_week are required.",
        });
    }

    try {
        const { data, error } = await supabase
            .from("care_routines")
            .insert({
                dog_id,
                title,
                activity_type,
                schedule_time,
                days_of_week,
                is_active: is_active ?? undefined,
            })
            .select()
            .single();

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to create routine",
            });
        }

        return res.status(201).json({
            message: "Routine created successfully.",
            data: data,
        });
    } catch (error) {
        console.error("Create routine error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * @route   PATCH /:routineId
 * @desc    Update an existing routine.
 * @access  Private
 */
router.patch("/:routineId", authenticateToken, async (req, res) => {
    const { routineId } = req.params;

    const updates = cleanPayload(req.body);

    if (Object.keys(updates).length === 0) {
        return res
            .status(400)
            .json({ error: "No fields provided for update." });
    }

    try {
        const { data, error } = await supabase
            .from("routines")
            .update(updates)
            .eq("id", routineId)
            .select()
            .single();

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to update routine",
            });
        }

        return res.status(200).json({
            message: `Routine ${routineId} updated successfully.`,
            data: data,
        });
    } catch (error) {
        console.error("Update routine error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * @route   DELETE /:routineId
 * @desc    Deletes a routine.
 * @access  Private
 */
router.delete("/:routineId", authenticateToken, async (req, res) => {
    const { routineId } = req.params;

    try {
        const { data, error } = await supabase
            .from("routines")
            .delete()
            .eq("id", routineId);

        if (error || !data) {
            return res.status(404).json({
                error: "Routine not found",
            });
        }

        return res.status(200).json({
            message: "Routine deleted successfully",
        });
    } catch (error) {
        console.error("Delete routine error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

export default router;
