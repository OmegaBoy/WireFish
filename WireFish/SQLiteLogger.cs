using Microsoft.Data.Sqlite;

namespace WireFish
{

    public class SQLiteLogger
    {
        private string connectionString;

        public SQLiteLogger(string dbFilePath)
        {
            connectionString = $"Data Source={dbFilePath}";
        }

        public void Log(string message, object? obj = null)
        {
            using (var connection = new SqliteConnection(connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = "INSERT INTO Log (Message) VALUES (@message)";
                command.Parameters.AddWithValue("@message", message);
                command.ExecuteNonQuery();
            }
        }
    }

}
