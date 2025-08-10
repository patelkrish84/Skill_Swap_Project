import userModel from "../models/userModels.js";

export const getUserData = async (req, res) => {
    try {
        // If userAuth middleware sets req.userId from token
        const userId = req.userId || req.body.userId || req.query.userId;

        if (!userId) {
            return res.json({ success: false, message: 'User ID is required' });
        }

        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: 'User not Found' });
        }

        res.json({
            success: true,
            UserData: {
                name: user.name,
                isAccountVerified: user.isAccountVerified
            }
        });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};
