import express from "express";
import { supabase } from "../config/supabase.js";
import { authenticateToken } from "../middlewares/auth.js";
import { GoogleGenAI } from "@google/genai";

const router = express.Router();

/**
 * @route   GET /:dogId
 * @desc    Retrieves a list of all chat threads for a specific dog.
 * @access  Private
 */
router.get("/:dogId", authenticateToken, async (req, res) => {
    const { dogId } = req.params;

    try {
        const { data, error } = await supabase
            .from("ai_chats")
            .select("*")
            .eq("dog_id", dogId)
            .order("updated_at", { ascending: false });

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to retrieve chat threads",
            });
        }

        return res.status(200).json({
            message: `Chat threads for dog ${dogId} retrieved successfully.`,
            data: data,
        });
    } catch (error) {
        console.error("Get chats error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

/**
 * @route   GET /:chatId
 * @desc    Retrieves a chat thread.
 * @access  Private
 */
router.get("/:chatId", authenticateToken, async (req, res) => {
    const { chatId } = req.params;

    try {
        const { data, error } = await supabase
            .from("ai_chats")
            .select("*")
            .eq("id", chatId)
            .single();

        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to retrieve chat thread",
            });
        }

        return res.status(200).json({
            message: `Chat thread ${chatId} retrieved successfully.`,
            data: data,
        });
    } catch (error) {
        console.error("Get chat error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

/**
 * @route   POST /new
 * @desc    Starts a new chat thread and processes the user's first message.
 * @access  Private
 */
router.post("/new", authenticateToken, async (req, res) => {
    const { dog_id, message_text } = req.body;

    if (!dog_id || !message_text) {
        return res.status(400).json({
            error: "dog_id and message_text are required to start a chat.",
        });
    }

    try {
        const { data: newChat, error: chatError } = await supabase
            .from("ai_chats")
            .insert({ dog_id })
            .select("id")
            .single();

        if (chatError) {
            return res.status(500).json({
                error: chatError.message || "Failed to create chat thread",
            });
        }

        const chat_id = newChat.id;

        await supabase.from("ai_chat_messages").insert({
            chat_id,
            sender: "user",
            message_text,
        });

        // --- STEP 3: Return success and the ID for the next API call ---
        // NOTE: The actual AI processing (fetching context, calling GPT) happens in a separate, dedicated endpoint
        // or a background job to avoid timeouts, and usually involves a client-side follow-up call.

        return res.status(201).json({
            message: "New chat thread started and message saved.",
            chat_id: chat_id,
        });
    } catch (error) {
        console.error("Start new chat error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * @route   DELETE /:chatId
 * @desc    Deletes an entire chat thread and all associated messages.
 * @access  Private
 */
router.delete("/:chatId", authenticateToken, async (req, res) => {
    const { chatId } = req.params;
    try {
        const { data, error } = await supabase
            .from("ai_chats")
            .delete()
            .eq("id", chatId);

        if (error || !data) {
            return res.status(404).json({
                error: "Chat thread not found",
            });
        }

        return res.status(200).json({
            message: "Chat thread deleted successfully",
        });
    } catch (error) {
        console.error("Delete chat thread error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

const genAI = new GoogleGenAI(process.env.GOOGLE_GENAI_API_KEY);

/**
 * @route   POST /message
 * @desc    Inserts a new user message, fetches context, triggers AI response.
 * @access  Private
 */
router.post("/message", authenticateToken, async (req, res) => {
    const { chat_id, message_text } = req.body;

    if (!chat_id || !message_text) {
        return res
            .status(400)
            .json({ error: "chat_id and message_text are required." });
    }

    try {
        const { data: existingMessages } = await supabase
            .from("ai_chat_messages")
            .select("*")
            .eq("chat_id", chat_id)
            .order("created_at", { ascending: true })
            .limit(2);

        let userMessage;

        const isInitialDuplicate =
            existingMessages.length === 1 &&
            existingMessages[0].sender === "user" &&
            existingMessages[0].message_text === message_text;

        if (!isInitialDuplicate) {
            const { data, error: insertError } = await supabase
                .from("ai_chat_messages")
                .insert({ chat_id, sender: "user", message_text })
                .select()
                .single();

            if (insertError) {
                statusCode = insertError.code === "42501" ? 403 : 500;
                return res.status(statusCode).json({
                    error: "Failed to save user message.",
                    details: insertError.message,
                });
            }

            userMessage = data;
        } else {
            userMessage = existingMessages[0];
        }

        // --- STEP 2: Fetch Context ---
        const { data: chatHeader, error: headerError } = await supabase
            .from("ai_chats")
            .select("dog_id")
            .eq("id", chat_id)
            .single();

        if (headerError || !chatHeader) {
            return res
                .status(404)
                .json({ error: "Chat thread not found or access denied." });
        }

        const dog_id = chatHeader.dog_id;

        const [dogProfile, recentLogs, recentMessages] = await Promise.all([
            supabase.from("dogs").select("*").eq("id", dog_id).single(),
            supabase
                .from("activity_logs")
                .select("activity_type, note, occurred_at")
                .eq("dog_id", dog_id)
                .gte(
                    "occurred_at",
                    new Date(Date.now() - 48 * 3600 * 1000).toISOString()
                ),
            supabase
                .from("ai_chat_messages")
                .select("sender, message_text")
                .eq("chat_id", chat_id)
                .order("created_at", { ascending: true })
                .limit(10),
        ]);

        // --- STEP 3: Build message array for Google GenAI ---
        const systemPrompt = `You are FurMind, a compassionate canine health assistant. 
- DOG PROFILE: ${JSON.stringify(dogProfile.data || {})}
- RECENT ACTIVITY (48h): ${JSON.stringify(recentLogs.data || [])}
- RULES: Never give diagnosis; always recommend vet if serious. Keep responses warm and concise.`;

        const history = (recentMessages.data || [])
            .filter((msg) => msg.id !== userMessage.id) // Filter out the current message if it was just inserted
            .map((msg) => ({
                role: msg.sender === "user" ? "user" : "model",
                parts: [{ text: msg.message_text }],
            }));

        // The final message list includes the entire history and the current user query
        const contents = [
            ...history,
            { role: "user", parts: [{ text: message_text }] }, // Current user query
        ];

        // --- STEP 4: Call Google Generative AI ---
        // NOTE: The model and configuration must be set up correctly outside this function.
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-pro" });

        const genAIResponse = await model.generateContent({
            contents: contents, // Pass the formatted history + current query
            config: {
                systemInstruction: systemPrompt, // Pass the system prompt separately
                temperature: 0.7,
            },
        });

        // Extract AI text
        const aiResponseText = genAIResponse.text;

        // --- STEP 5: Save AI's Response ---
        const { data: aiMessage, error: aiInsertError } = await supabase
            .from("ai_chat_messages")
            .insert({ chat_id, sender: "ai", message_text: aiResponseText })
            .select()
            .single();

        if (aiInsertError)
            console.error("Failed to save AI response:", aiInsertError);

        // --- STEP 6: Return to client ---
        return res.status(200).json({
            message: "AI response received.",
            data: {
                user_message: userMessage,
                ai_response: aiMessage || {
                    chat_id,
                    sender: "ai",
                    message_text: aiResponseText,
                },
            },
        });
    } catch (error) {
        console.error("Full AI Chat process error:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * @route   GET /messages/:chatId
 * @desc    Retrieves all messages within a specific chat thread, ordered chronologically.
 * @access  Private
 */
router.get("/messages/:chatId", authenticateToken, async (req, res) => {
    const { chatId } = req.params;

    try {
        const { data: messages, error } = await supabase
            .from("ai_chat_messages")
            .select("*")
            .eq("chat_id", chatId)
            .order("created_at", { ascending: true });
        if (error) {
            return res.status(500).json({
                error: error.message || "Failed to retrieve chat messages",
            });
        }

        return res.status(200).json({
            message: `Messages for chat ${chatId} retrieved successfully.`,
            data: messages || [],
        });
    } catch (error) {
        console.error("Get messages error:", error);
        return res.status(500).json({
            error: "Internal server error",
        });
    }
});

export default router;
