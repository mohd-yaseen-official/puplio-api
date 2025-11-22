import express from "express";
import supabase from "../config/supabase.js";
import { authenticateToken } from "../middleware/auth.js";

const router = express.Router();

/**
 * @route   GET /
 * @desc    Get all dog profiles for authenticated user
 * @access  Private
 */
router.get("/", authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase.from("dog_profiles").select("*");

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to retrieve dog profiles",
            });
        }

        return res.status(200).json({
            message: "Dog profiles retrieved successfully",
            data: data,
        });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * @route   GET /dogs/:id
 * @desc    Get a specific dog profile for the logged in user
 * @access  Private
 */
router.get("/:id", authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const uuidRegex =
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(id)) {
            return res.status(400).json({
                error: "Invalid dog profile ID format",
            });
        }

        const { data, error } = await supabase
            .from("dog_profiles")
            .select("*")
            .eq("id", id)
            .single();

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to fetch dog profile",
            });
        }

        if (!data) {
            return res.status(404).json({
                error: "Dog profile not found",
            });
        }

        return res.status(200).json({
            message: "Dog profile retrieved successfully",
            data: data,
        });
    } catch (error) {
        console.error("Get dog profile error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

/**
 * @route   POST /dogs
 * @desc    Create a new dog profile for the logged in user
 * @access  Private
 */
router.post("/", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const { name, breed, age, weight, gender, medical_conditions } =
            req.body;

        if (!name) {
            return res.status(400).json({
                error: "Dog name is required",
            });
        }

        const validGenders = ["male", "female", "unknown"];
        if (gender && !validGenders.includes(gender)) {
            return res.status(400).json({
                error: "Invalid gender value",
            });
        }

        const { data, error } = await supabase
            .from("dog_profiles")
            .insert([
                {
                    name,
                    breed: breed || undefined,
                    age: age ?? null,
                    weight: weight ?? null,
                    gender: gender || undefined,
                    medical_conditions: medical_conditions || null,
                    owner_id: userId,
                },
            ])
            .select()
            .single();

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to create dog profile",
            });
        }

        return res.status(201).json({
            message: "Dog profile created successfully",
            data,
        });
    } catch (error) {
        console.error("Create dog profile error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

/**
 * @route   PATCH /:id
 * @desc    Update an existing dog profile for the logged in user
 * @access  Private
 */
router.patch("/:id", authenticateToken, async (req, res) => {
    try {
        const dogId = req.params.id;

        const { name, breed, age, weight, gender, medical_conditions } =
            req.body;

        const validGenders = ["male", "female", "unknown"];
        if (gender && !validGenders.includes(gender)) {
            return res.status(400).json({
                error: "Invalid gender value",
            });
        }

        const updatePayload = {
            name: name ?? undefined,
            breed: breed ?? undefined,
            age: age ?? undefined,
            weight: weight ?? undefined,
            gender: gender ?? undefined,
            medical_conditions: medical_conditions ?? undefined,
        };

        const { data, error } = await supabase
            .from("dog_profiles")
            .update(updatePayload)
            .eq("id", dogId)
            .select()
            .single();

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to update dog profile",
            });
        }

        return res.status(200).json({
            message: "Dog profile updated successfully",
            data,
        });
    } catch (error) {
        console.error("Update dog profile error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

/**
 * @route   DELETE /:id
 * @desc    Delete an existing dog profile for the logged in user
 * @access  Private
 */
router.delete("/:id", authenticateToken, async (req, res) => {
    try {
        const dogId = req.params.id;

        const { data, error } = await supabase
            .from("dog_profiles")
            .delete()
            .eq("id", dogId);

        if (error || !data) {
            return res.status(404).json({
                error: "Dog profile not found",
            });
        }

        return res.status(200).json({
            message: "Dog profile deleted",
        });
    } catch (err) {
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

export default router;
