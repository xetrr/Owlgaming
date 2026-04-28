export type Lang = "en" | "ar";

export const translations = {
  en: {
    // Nav
    nav_home: "Home",
    nav_games: "Games",
    nav_harddrives: "Hard Drives",
    nav_accessories: "Accessories",
    nav_contact: "Contact",
    nav_favorites: "Favorites",
    nav_signIn: "Sign In",
    nav_signOut: "Sign Out",
    nav_myFavorites: "My Favorites",

    // Hero
    hero_badge: "Your Gaming Paradise",
    hero_title: "Welcome to",
    hero_subtitle: "GAMEARLY",
    hero_description: "Your ultimate destination for game data, hard drives, and gaming accessories. Experience gaming like never before with our premium collection.",
    hero_browseGames: "Browse Games",
    hero_orderHardDrive: "Order Hard Drive",

    // Features
    features_title: "Everything a Gamer Needs",
    features_subtitle: "From the latest game data to high-performance storage — all in one place.",
    features_games_title: "Game Data",
    features_games_desc: "Browse hundreds of PC games with detailed info, download sizes, ratings, and more. Find your next adventure.",
    features_drives_title: "Hard Drives",
    features_drives_desc: "HDDs, SSDs, NVMe drives for every budget. Store your entire game library without compromise.",
    features_accessories_title: "Accessories",
    features_accessories_desc: "Gaming peripherals, controllers, headsets, and more to complete your ultimate gaming setup.",

    // Why Us
    whyus_title: "Why Gamers Choose",
    whyus_fast_title: "Fast & Reliable",
    whyus_fast_desc: "Quick access to all game data and instant order processing via WhatsApp.",
    whyus_premium_title: "Premium Selection",
    whyus_premium_desc: "Curated catalog of top PC games from trusted sources.",
    whyus_allinone_title: "All-in-One",
    whyus_allinone_desc: "Games, drives, accessories — everything you need in one store.",

    // Games page
    games_title: "Game Data",
    games_search: "Search games...",
    games_loading: "Loading games...",
    games_empty_title: "No games yet",
    games_empty_desc: "Games you add from the admin panel will appear here. Check back soon!",
    games_noResults: "No games found matching",
    games_orderHardDrive: "Order Hard Drive",
    games_changeDrive: "Change Drive",

    // Hard Drives page
    hd_title: "Hard Drives & Storage",
    hd_subtitle: "High-performance storage solutions for gaming",
    hd_loading: "Loading products...",
    hd_empty_title: "No products yet",
    hd_empty_desc: "Hard drives and storage products added from the admin panel will appear here. Check back soon!",
    hd_order_whatsapp: "Order on WhatsApp",
    hd_capacity: "Capacity",
    hd_speed: "Speed",
    hd_price: "Price",

    // Accessories page
    acc_title: "Gaming Accessories",
    acc_subtitle: "Level up your setup",
    acc_loading: "Loading accessories...",
    acc_empty_title: "No accessories yet",
    acc_empty_desc: "Accessories added from the admin panel will appear here. Check back soon!",

    // Contact page
    contact_title: "Contact Us",
    contact_subtitle: "Get in touch with us for orders, inquiries, and support. We're here to help!",
    contact_whatsapp_desc: "Chat with us directly for fast replies",
    contact_phone_desc: "Call us during business hours",
    contact_facebook_desc: "Follow us and send us a message",
    contact_location_desc: "Find us on the map",
    contact_hours_title: "Business Hours",
    contact_hours_note: "WhatsApp messages are answered as quickly as possible even outside business hours.",
    contact_chat_btn: "Chat on WhatsApp Now",

    // Cart page
    cart_title: "Shopping Cart",
    cart_empty_title: "Your Cart is Empty",
    cart_empty_desc: "Add some games to get started!",
    cart_browse: "Browse Games",
    cart_summary: "Order Summary",
    cart_games: "Games",
    cart_totalSize: "Total Size",
    cart_placeOrder: "Place an Order",
    cart_continueShopping: "Continue Shopping",
    cart_orderIncludes: "Your order includes:",
    cart_include1: "Your Name & Phone Number",
    cart_include2: "Game Name, ID & Size",
    cart_include3: "Total Storage Required",
    cart_sendVia: "Download as PDF or send directly to WhatsApp",

    // Checkout modal
    checkout_title: "Place an Order",
    checkout_subtitle: "Fill in your details, then choose how to send",
    checkout_fullName: "Full Name",
    checkout_namePlaceholder: "Enter your name",
    checkout_phoneLabel: "Phone Number",
    checkout_phonePlaceholder: "e.g. 01012345678",
    checkout_nameRequired: "Name is required",
    checkout_phoneRequired: "Phone number is required",
    checkout_phoneInvalid: "Enter a valid phone number",
    checkout_chooseSend: "Choose how to send",
    checkout_downloadPDF: "Download PDF",
    checkout_generating: "Generating...",
    checkout_pdfNote: "Save order as a PDF file",
    checkout_whatsapp: "Send to WhatsApp",
    checkout_waNote: "Send order directly to us",
    checkout_cancel: "Cancel",

    // Auth modal
    auth_welcomeBack: "Welcome back",
    auth_joinUs: "Join {brand}",
    auth_loginSubtitle: "Sign in to access your favorites",
    auth_signupSubtitle: "Create a free account",
    auth_signIn: "Sign In",
    auth_signUp: "Sign Up",
    auth_username: "Username",
    auth_email: "Email",
    auth_password: "Password",
    auth_minChars: "Minimum 6 characters",
    auth_createAccount: "Create Account",
    auth_noAccount: "No account yet? ",
    auth_signUpFree: "Sign up free",
    auth_haveAccount: "Already have an account? ",
    auth_dbNotConnected: "Database not connected. Accounts unavailable.",
    auth_emailPassRequired: "Email and password are required",
    auth_usernameRequired: "Username is required",
    auth_passwordShort: "Password must be at least 6 characters",
    auth_accountCreated: "Account created! Check your email to confirm, then log in.",
    auth_wrongCreds: "Wrong email or password",
    auth_emailInUse: "This email is already in use",
    auth_confirmEmail: "Please confirm your email first",
    auth_wrongLogin: "Invalid login credentials",

    // GameCard
    card_selected: "Selected ✓",
    card_noSpace: "Not Enough Space",
    card_addToCart: "Add to Cart",
    card_added: "Added",

    // Hard Drive Picker Modal
    picker_title: "Choose Hard Drive Size",
    picker_subtitle: "We'll track remaining space automatically and alert you when it's full.",
    picker_confirm: "Confirm",
    picker_customLabel: "Or enter your available space (GB)",
    picker_customPlaceholder: "e.g. 1000",
    picker_unlimited: "🔓 Browse Without Space Limit",
    picker_cancel: "Cancel",
    picker_confirmPreset: "Confirm Selection",
    picker_net: "net",

    // Storage Tracker Bar
    tracker_remaining: "Remaining Space",
    tracker_used: "Total selected:",
    tracker_exceeded: "Exceeded by",
    tracker_unlimited: "Unlimited Browsing",
    tracker_removeDrive: "Remove Drive",

    // Footer
    footer_tagline: "Your premier destination for game data, hard drives, and gaming accessories. Gaming paradise awaits.",
    footer_followUs: "Follow Us",
    footer_navigation: "Navigation",
    footer_getInTouch: "Get In Touch",
    footer_rights: "All rights reserved.",
    footer_passion: "Made with passion for gaming",
    footer_gameData: "Game Data",
    footer_hardDrives: "Hard Drives",
    footer_myFavorites: "My Favorites",
    footer_contactUs: "Contact Us",

    // Profile page
    profile_title: "My Profile",
    profile_account: "Account Info",
    profile_username: "Username",
    profile_email: "Email",
    profile_signout: "Sign Out",

    // Favorites page
    fav_title: "My Favorites",
    fav_signInPrompt: "Sign in to save games to your favorites list and access them anytime.",
    fav_signInBtn: "Sign In to View Favorites",
    fav_loading: "Loading favorites...",
    fav_empty_title: "No favorites yet",
    fav_empty_desc: "Browse games and tap the heart icon to save them here.",
    fav_browsegames: "Browse Games",
    fav_browse: "Browse Games",
    fav_game: "game",
    fav_games: "games",
    fav_saved: "saved",

    // Mini cart widget
    minicart_title: "Cart",
    minicart_games: "games",
    minicart_size: "Total Size",
    minicart_price: "Total Price",
    minicart_reset: "Reset",
    minicart_checkout: "Checkout",

    // Pricing
    pricing_perGb: "Price per GB",
    pricing_currency: "EGP",

    // General
    explore: "Explore",

    // 404
    notFound_title: "Page Not Found",
    notFound_desc: "The page you're looking for doesn't exist. Let's get you back on track.",
    notFound_back: "Back to Home",
  },

  ar: {
    // Nav
    nav_home: "الرئيسية",
    nav_games: "الألعاب",
    nav_harddrives: "الهاردات",
    nav_accessories: "الإكسسوارات",
    nav_contact: "تواصل معنا",
    nav_favorites: "المفضلة",
    nav_signIn: "تسجيل الدخول",
    nav_signOut: "تسجيل الخروج",
    nav_myFavorites: "مفضلتي",

    // Hero
    hero_badge: "جنتك في الألعاب",
    hero_title: "مرحباً بك في",
    hero_subtitle: "GAMEARLY",
    hero_description: "وجهتك المثالية لبيانات الألعاب والهاردات وإكسسوارات الألعاب. استمتع بتجربة ألعاب لا مثيل لها مع مجموعتنا المميزة.",
    hero_browseGames: "تصفح الألعاب",
    hero_orderHardDrive: "اطلب هارد",

    // Features
    features_title: "كل ما يحتاجه اللاعب",
    features_subtitle: "من أحدث بيانات الألعاب إلى التخزين عالي الأداء — كل شيء في مكان واحد.",
    features_games_title: "بيانات الألعاب",
    features_games_desc: "تصفح مئات ألعاب الحاسب مع معلومات تفصيلية، أحجام التنزيل، التقييمات والمزيد. اكتشف مغامرتك القادمة.",
    features_drives_title: "الهاردات",
    features_drives_desc: "HDD وSSD وNVMe لكل ميزانية. خزن مكتبتك الكاملة من الألعاب دون أي تنازل.",
    features_accessories_title: "الإكسسوارات",
    features_accessories_desc: "ملحقات الألعاب، أجهزة التحكم، سماعات الرأس والمزيد لتكتمل بيئة الألعاب المثالية.",

    // Why Us
    whyus_title: "لماذا يختار اللاعبون",
    whyus_fast_title: "سريع وموثوق",
    whyus_fast_desc: "وصول سريع لبيانات الألعاب ومعالجة فورية للطلبات عبر واتساب.",
    whyus_premium_title: "اختيار مميز",
    whyus_premium_desc: "كتالوج منتقى من أفضل ألعاب الحاسب من مصادر موثوقة.",
    whyus_allinone_title: "الكل في واحد",
    whyus_allinone_desc: "الألعاب والهاردات والإكسسوارات — كل ما تحتاجه في متجر واحد.",

    // Games page
    games_title: "بيانات الألعاب",
    games_search: "ابحث عن ألعاب...",
    games_loading: "جارٍ تحميل الألعاب...",
    games_empty_title: "لا توجد ألعاب بعد",
    games_empty_desc: "الألعاب التي تضيفها من لوحة الإدارة ستظهر هنا. تفقد لاحقاً!",
    games_noResults: "لا توجد نتائج لـ",
    games_orderHardDrive: "اطلب هارد",
    games_changeDrive: "تغيير الهارد",

    // Hard Drives page
    hd_title: "الهاردات والتخزين",
    hd_subtitle: "حلول تخزين عالية الأداء للألعاب",
    hd_loading: "جارٍ تحميل المنتجات...",
    hd_empty_title: "لا توجد منتجات بعد",
    hd_empty_desc: "الهاردات ومنتجات التخزين المضافة من لوحة الإدارة ستظهر هنا. تفقد لاحقاً!",
    hd_order_whatsapp: "اطلب عبر واتساب",
    hd_capacity: "السعة",
    hd_speed: "السرعة",
    hd_price: "السعر",

    // Accessories page
    acc_title: "إكسسوارات الألعاب",
    acc_subtitle: "ارفع مستوى إعدادك",
    acc_loading: "جارٍ تحميل الإكسسوارات...",
    acc_empty_title: "لا توجد إكسسوارات بعد",
    acc_empty_desc: "الإكسسوارات المضافة من لوحة الإدارة ستظهر هنا. تفقد لاحقاً!",

    // Contact page
    contact_title: "تواصل معنا",
    contact_subtitle: "تواصل معنا للطلبات والاستفسارات والدعم. نحن هنا للمساعدة!",
    contact_whatsapp_desc: "تحدث معنا مباشرة للردود السريعة",
    contact_phone_desc: "اتصل بنا خلال ساعات العمل",
    contact_facebook_desc: "تابعنا وأرسل لنا رسالة",
    contact_location_desc: "ابحث عنا على الخريطة",
    contact_hours_title: "ساعات العمل",
    contact_hours_note: "يتم الرد على رسائل واتساب في أقرب وقت ممكن حتى خارج ساعات العمل.",
    contact_chat_btn: "تحدث عبر واتساب الآن",

    // Cart page
    cart_title: "سلة التسوق",
    cart_empty_title: "سلتك فارغة",
    cart_empty_desc: "أضف ألعاباً للبدء!",
    cart_browse: "تصفح الألعاب",
    cart_summary: "ملخص الطلب",
    cart_games: "الألعاب",
    cart_totalSize: "الحجم الكلي",
    cart_placeOrder: "تقديم الطلب",
    cart_continueShopping: "متابعة التسوق",
    cart_orderIncludes: "طلبك يتضمن:",
    cart_include1: "اسمك ورقم هاتفك",
    cart_include2: "اسم اللعبة والمعرف والحجم",
    cart_include3: "إجمالي التخزين المطلوب",
    cart_sendVia: "تنزيل كـ PDF أو إرسال مباشرة عبر واتساب",

    // Checkout modal
    checkout_title: "تقديم الطلب",
    checkout_subtitle: "أدخل بياناتك ثم اختر طريقة الإرسال",
    checkout_fullName: "الاسم الكامل",
    checkout_namePlaceholder: "أدخل اسمك",
    checkout_phoneLabel: "رقم الهاتف",
    checkout_phonePlaceholder: "مثال: 01012345678",
    checkout_nameRequired: "الاسم مطلوب",
    checkout_phoneRequired: "رقم الهاتف مطلوب",
    checkout_phoneInvalid: "أدخل رقم هاتف صحيح",
    checkout_chooseSend: "اختر طريقة الإرسال",
    checkout_downloadPDF: "تنزيل PDF",
    checkout_generating: "جارٍ الإنشاء...",
    checkout_pdfNote: "حفظ الطلب كملف PDF",
    checkout_whatsapp: "إرسال عبر واتساب",
    checkout_waNote: "إرسال الطلب مباشرة إلينا",
    checkout_cancel: "إلغاء",

    // Auth modal
    auth_welcomeBack: "مرحباً مجدداً",
    auth_joinUs: "انضم إلى {brand}",
    auth_loginSubtitle: "سجل دخولك للوصول إلى مفضلتك",
    auth_signupSubtitle: "أنشئ حساباً مجانياً",
    auth_signIn: "تسجيل الدخول",
    auth_signUp: "إنشاء حساب",
    auth_username: "اسم المستخدم",
    auth_email: "البريد الإلكتروني",
    auth_password: "كلمة المرور",
    auth_minChars: "٦ أحرف على الأقل",
    auth_createAccount: "إنشاء الحساب",
    auth_noAccount: "ليس لديك حساب؟ ",
    auth_signUpFree: "سجل مجاناً",
    auth_haveAccount: "لديك حساب بالفعل؟ ",
    auth_dbNotConnected: "قاعدة البيانات غير متصلة. الحسابات غير متاحة.",
    auth_emailPassRequired: "البريد وكلمة المرور مطلوبان",
    auth_usernameRequired: "اسم المستخدم مطلوب",
    auth_passwordShort: "كلمة المرور يجب أن تكون ٦ أحرف على الأقل",
    auth_accountCreated: "تم إنشاء الحساب! تحقق من بريدك الإلكتروني للتأكيد ثم سجل الدخول.",
    auth_wrongCreds: "البريد الإلكتروني أو كلمة المرور خاطئة",
    auth_emailInUse: "هذا البريد الإلكتروني مستخدم بالفعل",
    auth_confirmEmail: "يرجى تأكيد بريدك الإلكتروني أولاً",
    auth_wrongLogin: "بيانات الدخول غير صحيحة",

    // GameCard
    card_selected: "تم الاختيار ✓",
    card_noSpace: "لا يسعه الهارد",
    card_addToCart: "إضافة إلى السلة",
    card_added: "مضاف",

    // Hard Drive Picker Modal
    picker_title: "اختر سعة الهارد",
    picker_subtitle: "سنقوم بحساب المساحة المتبقية تلقائياً وتنبيهك عند امتلاء الهارد.",
    picker_confirm: "تأكيد",
    picker_customLabel: "أو أدخل المساحة المتوفرة لديك (GB)",
    picker_customPlaceholder: "مثال: 1000",
    picker_unlimited: "🔓 تصفح بدون تقيد بالمساحة",
    picker_cancel: "إلغاء",
    picker_confirmPreset: "تأكيد الاختيار",
    picker_net: "صافي",

    // Storage Tracker Bar
    tracker_remaining: "المساحة المتبقية",
    tracker_used: "مجموع المحدد:",
    tracker_exceeded: "تجاوزت الحد بـ",
    tracker_unlimited: "تصفح بلا حدود",
    tracker_removeDrive: "إلغاء الهارد",

    // Footer
    footer_tagline: "وجهتك المثالية لبيانات الألعاب والهاردات وإكسسوارات الألعاب. جنتك في الألعاب بانتظارك.",
    footer_followUs: "تابعنا",
    footer_navigation: "التصفح",
    footer_getInTouch: "تواصل معنا",
    footer_rights: "جميع الحقوق محفوظة.",
    footer_passion: "صُنع بشغف للألعاب",
    footer_gameData: "بيانات الألعاب",
    footer_hardDrives: "الهاردات",
    footer_myFavorites: "مفضلتي",
    footer_contactUs: "تواصل معنا",

    // Profile page
    profile_title: "ملفي الشخصي",
    profile_account: "معلومات الحساب",
    profile_username: "اسم المستخدم",
    profile_email: "البريد الإلكتروني",
    profile_signout: "تسجيل الخروج",

    // Favorites page
    fav_title: "مفضلتي",
    fav_signInPrompt: "سجل دخولك لحفظ ألعابك في قائمة المفضلة والوصول إليها في أي وقت.",
    fav_signInBtn: "تسجيل الدخول لعرض المفضلة",
    fav_loading: "جارٍ تحميل المفضلة...",
    fav_empty_title: "لا توجد مفضلة بعد",
    fav_empty_desc: "تصفح الألعاب واضغط على القلب لحفظها هنا.",
    fav_browsegames: "تصفح الألعاب",
    fav_browse: "تصفح الألعاب",
    fav_game: "لعبة",
    fav_games: "ألعاب",
    fav_saved: "محفوظة",

    // Mini cart widget
    minicart_title: "السلة",
    minicart_games: "ألعاب",
    minicart_size: "الحجم الكلي",
    minicart_price: "السعر الكلي",
    minicart_reset: "إعادة تعيين",
    minicart_checkout: "إتمام الطلب",

    // Pricing
    pricing_perGb: "سعر الجيجابايت",
    pricing_currency: "جنيه",

    // General
    explore: "استكشف",

    // 404
    notFound_title: "الصفحة غير موجودة",
    notFound_desc: "الصفحة التي تبحث عنها غير موجودة. دعنا نعيدك إلى المسار الصحيح.",
    notFound_back: "العودة للرئيسية",
  },
} as const;

export type TranslationKey = keyof typeof translations.en;
