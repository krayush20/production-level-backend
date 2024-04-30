import { Router } from "express";
import { registerUser,loginUser, logoutUser, refreshAccessToken, updateAvatar, updateCoverImage, updatePassword,updateUserNameAndFullName,getUserChannelProfile, getWatchHistory } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router()

router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser)
    router.route("/login").post(loginUser)
    // secure route
    router.route("/logout").post(verifyJWT,logoutUser)
    router.route("/refresh-token").post(refreshAccessToken)
    router.route("/update-profile").patch(verifyJWT,updateUserNameAndFullName)
    router.route("/update-password").patch(verifyJWT,updatePassword)
    
    router.route("/user-channel-profile").post(verifyJWT,getUserChannelProfile)

    router.route("/update-avatar").patch(verifyJWT, upload.single("avatar"), updateAvatar)
    router.route("/update-cover-image").patch(verifyJWT, upload.single("coverImage"), updateCoverImage)
    
    router.route("/history").get(verifyJWT, getWatchHistory)
    
export default router