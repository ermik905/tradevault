module.exports = route;

if (require.main === module) {
  const server = http.createServer((req, res) => {
    route(req, res).catch(err => {
      console.error("SERVER ERROR:", err);

      send(res, 500, {
        error: "Server error."
      });
    });
  });

  server.listen(PORT, HOST, () => {
    console.log(`TradeVault running on port ${PORT}`);
    console.log("Database: Supabase");
    console.log("Owner: " + OWNER_EMAIL);
    console.log(
      "Admins: " +
      Array.from(ADMIN_EMAILS).join(", ")
    );
  });
}
