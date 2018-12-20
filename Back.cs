using System;
using System.Threading.Tasks;

public interface IBackgroundWorker
{
    Task<TOutput> Run<TInput, TOutput>(Func<TInput, TOutput> action);
    Task Run(Action action);
    Task Run<TInput>(Action<TInput> action);
}

public sealed class BackgroundWorker : IBackgroundWorker
{
    public Task<TOutput> Run<TInput, TOutput>(Func<TInput, TOutput> action)
    {
        return Task<TOutput>.Factory.StartNew(() =>
        {
            var service = DependencyResolver.Current.GetService<TInput>();
            return action(service);
        }, TaskCreationOptions.LongRunning);
    }

    public Task Run(Action action)
    {
        return Task.Factory.StartNew(action, TaskCreationOptions.LongRunning);
    }

    public Task Run<TInput>(Action<TInput> action)
    {
        return Task.Factory.StartNew(() =>
        {
            var service = DependencyResolver.Current.GetService<TInput>();
            action(service);
        }, TaskCreationOptions.LongRunning);
    }
}