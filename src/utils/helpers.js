export const cleanPayload = (body) => {
    const payload = {};
    const FORBIDDEN_KEYS = ["user_id", "owner_id", "dog_id", "id"];

    for (const key in body) {
        if (body[key] !== null && typeof body[key] !== "undefined") {
            if (!FORBIDDEN_KEYS.includes(key)) {
                payload[key] = body[key];
            }
        }
    }
    return payload;
};
