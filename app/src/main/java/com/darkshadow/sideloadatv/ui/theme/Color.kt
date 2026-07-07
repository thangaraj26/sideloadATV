package com.darkshadow.sideloadatv.ui.theme

import androidx.compose.ui.graphics.Color

// --- Brand palette (indigo accent) -----------------------------------------
// Fixed, intentional colors rather than the stock dynamic purple, so the app
// reads as one designed surface across devices. Dynamic color stays available
// behind a flag in SideloadATVTheme for users who prefer it.

// Light scheme
val IndigoPrimaryLight = Color(0xFF4B5BD7)
val IndigoOnPrimaryLight = Color(0xFFFFFFFF)
val IndigoContainerLight = Color(0xFFE0E1FF)
val IndigoOnContainerLight = Color(0xFF00105C)
val SecondaryLight = Color(0xFF5A5D72)
val SecondaryContainerLight = Color(0xFFDFE0F9)
val OnSecondaryContainerLight = Color(0xFF171A2C)
val TertiaryLight = Color(0xFF77536D)
val BackgroundLight = Color(0xFFFBF8FF)
val OnBackgroundLight = Color(0xFF1B1B21)
val SurfaceVariantLight = Color(0xFFE3E1EC)
val OnSurfaceVariantLight = Color(0xFF46464F)
val OutlineLight = Color(0xFF777680)

// Dark scheme
val IndigoPrimaryDark = Color(0xFFBFC2FF)
val IndigoOnPrimaryDark = Color(0xFF14239B)
val IndigoContainerDark = Color(0xFF333CB0)
val IndigoOnContainerDark = Color(0xFFE0E1FF)
val SecondaryDark = Color(0xFFC3C5DD)
val SecondaryContainerDark = Color(0xFF424659)
val OnSecondaryContainerDark = Color(0xFFDFE0F9)
val TertiaryDark = Color(0xFFE6BAD7)
val BackgroundDark = Color(0xFF121318)
val OnBackgroundDark = Color(0xFFE4E1E9)
val SurfaceVariantDark = Color(0xFF46464F)
val OnSurfaceVariantDark = Color(0xFFC7C5D0)
val OutlineDark = Color(0xFF918F9A)

// --- Semantic status colors (not part of the M3 scheme) ---------------------
// Used by status chips / expiry badges. Kept out of the color scheme because
// M3 has no "success"/"warning" role.
val SuccessLight = Color(0xFF2E6B34)
val SuccessContainerLight = Color(0xFFB3F1AF)
val WarningLight = Color(0xFF8A5300)
val WarningContainerLight = Color(0xFFFFDDB3)

val SuccessDark = Color(0xFF98D894)
val SuccessContainerDark = Color(0xFF11500F)
val WarningDark = Color(0xFFFFB95C)
val WarningContainerDark = Color(0xFF684000)
