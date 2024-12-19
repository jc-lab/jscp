export class Channel<T> {
    private buffer: T[] = [];
    private readonly capacity: number;
    private closed = false;
    private senders: Array<(value: boolean) => void> = [];
    private receivers: Array<(value: T | undefined) => void> = [];

    constructor(capacity: number = 0) {
        this.capacity = capacity;
    }

    // Send value to channel
    async send(value: T): Promise<boolean> {
        if (this.closed) {
            throw new Error('Cannot send on closed channel');
        }

        // If there are waiting receivers, send directly to them
        if (this.receivers.length > 0) {
            const receiver = this.receivers.shift()!;
            receiver(value);
            return true;
        }

        // If buffer has space, add to buffer
        if (this.capacity > 0 && this.buffer.length < this.capacity) {
            this.buffer.push(value);
            return true;
        }

        // Otherwise, wait for a receiver
        return new Promise<boolean>((resolve) => {
            this.buffer.push(value);
            this.senders.push(resolve);
        });
    }

    // Receive value from channel
    async receive(): Promise<T | undefined> {
        if (this.closed && this.buffer.length === 0) {
            return undefined;
        }

        // If buffer has values, return from buffer
        if (this.buffer.length > 0) {
            const value = this.buffer.shift()!;

            // If there are waiting senders, let one send
            if (this.senders.length > 0) {
                const sender = this.senders.shift()!;
                sender(true);
            }

            return value;
        }

        // If channel is not closed but empty, wait for sender
        if (!this.closed) {
            return new Promise<T>((resolve) => {
                this.receivers.push(resolve as any);
            });
        }

        return undefined;
    }

    // Close the channel
    close(): void {
        this.closed = true;

        // Resolve all waiting receivers with undefined
        while (this.receivers.length > 0) {
            const receiver = this.receivers.shift()!;
            receiver(undefined);
        }

        // Resolve all waiting senders with false
        while (this.senders.length > 0) {
            const sender = this.senders.shift()!;
            sender(false);
        }
    }

    // Check if channel is closed
    isClosed(): boolean {
        return this.closed;
    }
}