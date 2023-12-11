namespace LocacaoDeCarros.Identity.API.Application
{
    public class Message
    {
        public DateTime Timestamp { get; set; }

        public Message()
        {
            Timestamp = DateTime.Now;
        }
    }
}
